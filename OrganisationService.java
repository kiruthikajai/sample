package com.insurercore.serviceactivators;

import static com.insurercore.constants.InsurerCoreConstant.BEARER_AUTHORIZATION_HEADER;
import static com.insurercore.constants.InsurerCoreConstant.HEADER_ORGANISATION_ID;
import static com.insurercore.constants.InsurerCoreConstant.HEADER_REQUESTOR_ID;
import static com.insurercore.constants.InsurerCoreConstant.HEADER_STATUS_TYPE;
import static com.insurercore.constants.InsurerCoreConstant.LIST_LIMIT;
import static com.insurercore.constants.InsurerCoreConstant.PAGE_NO;
import static com.insurercore.constants.InsurerCoreConstant.TOTAL_ITEMS;
import static com.insurercore.exception.ErrorScenario.DUPLICATE_ORGANISATION;
import static com.insurercore.exception.ErrorScenario.OPERATION_NOT_ALLOWED;
import static com.insurercore.exception.ErrorScenario.ORGANISATION_CREATION_ERROR;
import static com.insurercore.exception.ErrorScenario.ORGANISATION_DOES_NOT_EXIST;
import static com.insurercore.exception.ErrorScenario.TWITTER_PROFILE_NAME_DOES_NOT_EXIST;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.LinkedList;
import java.util.List;

import javax.imageio.ImageIO;

import org.apache.camel.Body;
import org.apache.camel.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.insurercore.entity.Member;
import com.insurercore.entity.MemberSpecialization;
import com.insurercore.entity.Organisation;
import com.insurercore.exception.OperationProhibitedException;
import com.insurercore.exception.OrganisationCreationException;
import com.insurercore.exception.OrganisationDoesNotExistException;
import com.insurercore.exception.OrganisationExistException;
import com.insurercore.exception.SequenceIdGenerationException;
import com.insurercore.exception.TwitterProfileNameDoesNotExistException;
import com.insurercore.models.types.StatusType;
import com.insurercore.repositories.MemberRepository;
import com.insurercore.repositories.MemberSpecializationRepository;
import com.insurercore.repositories.OrganisationRepository;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.User;
import twitter4j.conf.ConfigurationBuilder;

/**
 * Service to call MongoDB for operations for {@link Organisation}.
 *
 * @author Sanjay Kumar
 */
@Component(value = "organisationService")
@Service
@PropertySource("file:config/twitter4j.properties")
public class OrganisationService {
    @Value("${oauth.consumerKey}")
    private String consumerKey;

    @Value("${oauth.consumerSecret}")
    private String consumerSecret;

    @Value("${oauth.accessToken}")
    private String accessToken;

    @Value("${oauth.accessTokenSecret}")
    private String accessTokenSecret;

    @Autowired
    private OrganisationRepository organisationRepository;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private MongoTemplate mongoTemplate;

    @Autowired
    private MemberSpecializationRepository memberSpecializationRepository;

    @Autowired
    private SequenceIdService sequenceIdService;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${insurer.core.api.get.org.limit:10}")
    private int organisationListLimit;

    Logger LOGGER = LoggerFactory.getLogger(OrganisationService.class.getCanonicalName());

    /**
     * Method saves a {@link Organisation} in DB.
     *
     * @param org
     * @param exchange
     * @throws SequenceIdGenerationException
     */
    public void saveOrganisation(@Body Organisation org, Exchange exchange)
            throws SequenceIdGenerationException, OrganisationExistException, OrganisationCreationException {

        Organisation orgFromRepo = organisationRepository.getOrgWithNameAndRegNumber(org.getOrganisationName(),
                org.getRegistrationNumber());

        if (orgFromRepo != null) {
            LOGGER.error(DUPLICATE_ORGANISATION.getLogMessage(org.getOrganisationName(), org.getRegistrationNumber()));
            String[] params = { org.getOrganisationName(), org.getRegistrationNumber() };
            throw new OrganisationExistException(DUPLICATE_ORGANISATION, params);
        }

        org.setOrganisationId(getOrganisationId());

        org.setApprovedOrganisation(StatusType.TOBEAPPROVED);// by default
                                                             // organisation
                                                             // will be in to
                                                             // be approved
                                                             // status
        String encryptPassword = bCryptPasswordEncoder.encode(org.getRequestor().getPassword());

        org.getRequestor().setPassword(encryptPassword);

        org = organisationRepository.insert(org);

        if (org == null) {
            LOGGER.error(
                    ORGANISATION_CREATION_ERROR.getLogMessage(org.getOrganisationName(), org.getRegistrationNumber()));
            String[] params = { org.getOrganisationName(), org.getRegistrationNumber() };
            throw new OrganisationCreationException(ORGANISATION_CREATION_ERROR, params);
        }

        org.setId(null);
        exchange.getIn().setHeader(HEADER_ORGANISATION_ID, org.getOrganisationId());
        exchange.getIn().setBody(org);
    }

    /**
     * Method to update the {@link Organisation}.
     *
     * @param exchange
     * @throws OrganisationDoesNotExistException
     * @throws TwitterProfileNameDoesNotExistException
     */
    @SuppressWarnings("PMD.CollapsibleIfStatements")
    public void updateOrganisation(@Body Organisation organisation, Exchange exchange)
            throws OrganisationDoesNotExistException, OperationProhibitedException,
            TwitterProfileNameDoesNotExistException {

        String organisationId = exchange.getIn().getHeader(HEADER_ORGANISATION_ID, String.class);
        String requestorId = exchange.getIn().getHeader(HEADER_REQUESTOR_ID, String.class);

        Member requestor = memberRepository.findByMemberId(requestorId);

        if (requestor == null) {
            LOGGER.error(OPERATION_NOT_ALLOWED.getLogMessage(organisationId));
            throw new OperationProhibitedException(OPERATION_NOT_ALLOWED);

        } else if (!MemberService.isRequestorInsurerCoreAdmin(requestor))

            if (!MemberService.isRequestorOfSameOrganisation(requestor, organisationId)
                    && !MemberService.isRequestorSuperAdmin(requestor)) {

                LOGGER.error(OPERATION_NOT_ALLOWED.getLogMessage());
                throw new OperationProhibitedException(OPERATION_NOT_ALLOWED);
            }

        Organisation orgFromRepo = organisationRepository.findByOrganisationId(organisationId);

        if (orgFromRepo == null) {
            LOGGER.error(ORGANISATION_DOES_NOT_EXIST.getLogMessage(organisationId));
            throw new OrganisationDoesNotExistException(ORGANISATION_DOES_NOT_EXIST, organisationId);
        } else {
            orgFromRepo.setAddresses(organisation.getAddresses());
            orgFromRepo.setClassOfBusiness(organisation.getClassOfBusiness());
            orgFromRepo.setSummary(organisation.getSummary());

            if (organisation.getTwitterFlag() != null && organisation.getTwitterFlag().equalsIgnoreCase("yes")) {

                User twitterUser = twitterProfile(organisation.getTwitter());
                if (twitterUser == null) {
                    throw new TwitterProfileNameDoesNotExistException(TWITTER_PROFILE_NAME_DOES_NOT_EXIST);
                }

                LOGGER.info("twitter Profile Image " + twitterUser.getProfileImageURL());
                if (twitterUser.getProfileImageURL() != null) {
                    orgFromRepo.setCompanyLogo(convertByteArray(twitterUser.getOriginalProfileImageURL()));
                    orgFromRepo.setTwitterFlag(organisation.getTwitterFlag());
                }
                if (orgFromRepo.getCompanyInfo() == null || orgFromRepo.getCompanyInfo().isEmpty()) {

                    orgFromRepo.setCompanyInfo(twitterUser.getDescription());
                }

            } else {
                orgFromRepo.setCompanyInfo(organisation.getCompanyInfo());
                orgFromRepo.setCompanyLogo(organisation.getCompanyLogo());
            }
            orgFromRepo.setTwitter(organisation.getTwitter());
            orgFromRepo.setCompanyURL(organisation.getCompanyURL());
            orgFromRepo.setCreditRating(organisation.getCreditRating());
            orgFromRepo.setFcaNumber(organisation.getFcaNumber());
            orgFromRepo.setOrganisationType(organisation.getOrganisationType());
            orgFromRepo.setServiceType(organisation.getServiceType());
            orgFromRepo.setSubscriptionType(organisation.getSubscriptionType());
            orgFromRepo.setFacebook(organisation.getFacebook());
            orgFromRepo.setLinkedin(organisation.getLinkedin());

            String orgName = organisation.getOrganisationName();

            if (orgName != null && !orgName.isEmpty()) {
                orgFromRepo.setOrganisationName(orgName);
            }
            orgFromRepo = organisationRepository.save(orgFromRepo);

            if (MemberService.isRequestorInsurerCoreAdmin(requestor)) {
                List<Member> members = memberRepository.findByOrganisationId(organisationId);
                members.parallelStream().forEach(mems -> {
                    mems.setOrganisationName(orgName);
                    memberRepository.save(mems);
                });

                List<MemberSpecialization> memberData = memberSpecializationRepository
                        .findBySpecializationOrganisationId(organisationId);
                memberData.parallelStream().forEach(mems -> {
                    String memberDetails = null;
                    mems.getMemberId();
                    Member member = memberRepository.findByMemberId(mems.getMemberId());
                    memberDetails = member.getFirstName() + "," + member.getLastName() + "," + member.getEmailId() + ","
                            + member.getOrganisationName();
                    mems.setMemberDetails(memberDetails);

                });
                memberSpecializationRepository.save(memberData);
            }

        }
        orgFromRepo.setId(null);
        orgFromRepo.getRequestor().setPassword(null);
        exchange.getIn().setBody(orgFromRepo);

    }

    /**
     * Method to get the {@link Organisation}.
     *
     * @param exchange
     * @throws OrganisationDoesNotExistException
     */
    public void getOrganisation(Exchange exchange)
            throws OrganisationDoesNotExistException, OperationProhibitedException {

        String organisationId = exchange.getIn().getHeader(HEADER_ORGANISATION_ID, String.class);

        String requestorId = exchange.getIn().getHeader(HEADER_REQUESTOR_ID, String.class);

        Member requestor = memberRepository.findByMemberId(requestorId);

        if (requestor == null) {
            LOGGER.error(OPERATION_NOT_ALLOWED.getLogMessage());
            throw new OperationProhibitedException(OPERATION_NOT_ALLOWED);
        }

        Organisation organisation = organisationRepository.findByOrganisationId(organisationId);

        if (organisation == null) {
            LOGGER.error(ORGANISATION_DOES_NOT_EXIST.getLogMessage(organisationId));
            throw new OrganisationDoesNotExistException(ORGANISATION_DOES_NOT_EXIST, organisationId);
        }

        if (StatusType.APPROVED.equals(organisation.getApprovedOrganisation())
                || MemberService.isRequestorInsurerCoreAdmin(requestor)) {
            organisation.setId(null);
            organisation.getRequestor().setPassword(null);
            exchange.getIn().setBody(organisation);
        } else {
            LOGGER.warn("Organisation {} is not Approved. Requestor {} can't view it details. ", organisationId,
                    requestorId);
            exchange.getIn().setBody(new LinkedList<>());
        }
    }

    /**
     * Method to get the {@link Organisation}.
     *
     * @param exchange
     * @throws OrganisationDoesNotExistException
     */
    public void approveOrganisation(Exchange exchange)
            throws OrganisationDoesNotExistException, OperationProhibitedException {

        String organisationId = exchange.getIn().getHeader(HEADER_ORGANISATION_ID, String.class);
        StatusType statusType = exchange.getIn().getHeader(HEADER_STATUS_TYPE, StatusType.class);

        String requestorId = exchange.getIn().getHeader(HEADER_REQUESTOR_ID, String.class);

        Member requestor = memberRepository.findByMemberId(requestorId);

        if (!MemberService.isRequestorInsurerCoreAdmin(requestor)) {
            LOGGER.error(OPERATION_NOT_ALLOWED.getLogMessage());
            throw new OperationProhibitedException(OPERATION_NOT_ALLOWED);
        }

        Organisation organisation = organisationRepository.findByOrganisationId(organisationId);

        if (organisation == null) {
            LOGGER.error(ORGANISATION_DOES_NOT_EXIST.getLogMessage(organisationId));
            throw new OrganisationDoesNotExistException(ORGANISATION_DOES_NOT_EXIST, organisationId);
        }

        organisation.setApprovedOrganisation(statusType);

        organisation = organisationRepository.save(organisation);

        organisation.setId(null);
        organisation.getRequestor().setPassword(null);
        exchange.getIn().setBody(organisation);

    }

    /**
     * Method to get list of {@link com.insurercore.entity.Organisation}.
     *
     * @param exchange
     * @throws OrganisationDoesNotExistException
     */
    public void getOrganisationList(Exchange exchange)
            throws OrganisationDoesNotExistException, OperationProhibitedException {

        List<Organisation> organisationList = new LinkedList<>();

        /* ONLY INSURER_CORE_ADMIN can access this url */
        if (exchange.getIn().getHeader(BEARER_AUTHORIZATION_HEADER, Boolean.class)) {
            String requestorId = exchange.getIn().getHeader(HEADER_REQUESTOR_ID, String.class);

            Member requestor = memberRepository.findByMemberId(requestorId);

            if (!MemberService.isRequestorInsurerCoreAdmin(requestor)) {
                LOGGER.error(OPERATION_NOT_ALLOWED.getLogMessage());
                throw new OperationProhibitedException(OPERATION_NOT_ALLOWED);
            }

            int pageNumber = 0;
            int listSize = organisationListLimit;

            Integer page = exchange.getIn().getHeader(PAGE_NO, Integer.class);
            Integer limit = exchange.getIn().getHeader(LIST_LIMIT, Integer.class);

            if (page != null && page.intValue() != 0) {
                pageNumber = page.intValue();
            }
            if (limit != null && limit.intValue() != 0) {
                listSize = limit;
            }

            Page<Organisation> organisations = organisationRepository.findAll(new PageRequest(pageNumber, listSize));

            organisations.getContent().parallelStream().forEach(organisation -> {
                organisation.setId(null);
                organisation.getRequestor().setPassword(null);
                organisationList.add(organisation);
            });

            exchange.getIn().setHeader(PAGE_NO, pageNumber);
            exchange.getIn().setHeader(LIST_LIMIT, listSize);
            exchange.getIn().setHeader(TOTAL_ITEMS, organisations.getTotalElements());
            exchange.getIn().setBody(organisationList);
        } else {
            List<Organisation> organisations = organisationRepository
                    .getApprovedOrganisation(StatusType.APPROVED.toString());
            organisations.parallelStream().forEach(organisation -> {
                organisation.setId(null);
                organisation.getRequestor().setPassword(null);
                organisationList.add(organisation);
            });
            exchange.getIn().setBody(organisationList);
        }

    }

    private String getOrganisationId() throws SequenceIdGenerationException {

        return sequenceIdService.getNextOrganisationSequenceId();
    }

    private Organisation buildSafeToReturnOrg(Organisation org) {

        org.setId(null);
        org.getRequestor().setPassword("");
        return org;
    }

    private User twitterProfile(String screenName) {
        User user = null;
        try {
            ConfigurationBuilder cb = new ConfigurationBuilder();
            cb.setDebugEnabled(true).setOAuthConsumerKey(consumerKey).setOAuthConsumerSecret(consumerSecret)
                    .setOAuthAccessToken(accessToken).setOAuthAccessTokenSecret(accessTokenSecret);
            TwitterFactory tf = new TwitterFactory(cb.build());
            Twitter twitter = tf.getInstance();
            user = twitter.showUser(screenName);
        } catch (TwitterException te) {
            LOGGER.error("Failed to delete status: " + te.getMessage());
        }
        return user;
    }

    private byte[] convertByteArray(String profileImage) {
        byte[] imageBytes = null;
        try {
            URL url = new URL(profileImage);
            BufferedImage image = ImageIO.read(url);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "jpeg", baos);
            imageBytes = baos.toByteArray();
        } catch (MalformedURLException malformedURLException) {
            LOGGER.error("MalformedURLException " + malformedURLException.getMessage());
        } catch (IOException ioException) {
            LOGGER.error("IOException " + ioException.getMessage());
        }

        return imageBytes;
    }

}
