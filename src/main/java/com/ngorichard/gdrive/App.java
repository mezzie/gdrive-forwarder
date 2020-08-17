package com.ngorichard.gdrive;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.AbstractInputStreamContent;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.GmailScopes;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.Address;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.Session;
import javax.mail.internet.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

public class App {

    private static String gdriveCredPath;
    private static String gmailCredPath;
    private static final String TMP_GDRIVE_FOLDER = "/tmp/gdrive";
    private static final String LAST_ACCESSED_FILE = "last_accessed";

    private static final String APPLICATION_NAME = "gdrive forwarder";
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final String GDRIVE_TOKEN_DIRECTORY_PATH = "gDriveToken";
    private static final String GMAIL_TOKEN_DIRECTORY_PATH = "gmailToken";
    private static final Logger logger = LoggerFactory.getLogger(App.class);

    private static final List<String> GDRIVE_SCOPES = new ArrayList<>(DriveScopes.all());
    private static final List<String> GMAIL_SCOPES = Collections.singletonList(GmailScopes.MAIL_GOOGLE_COM);

    public static void main(String... args) throws IOException, GeneralSecurityException {

        logger.info("init");
        String credentialsPath = null, recipients = null, from = null, to = null, owner = null;
        if(args.length == 0) {
            System.out.println("Usage: java -jar gdrive-forwarder-1.0.jar <<PATH TO google OAUTH 2.0 GDrive Client json>> <<PATH TO google OAUTH 2.0 GMAIL Client json>> <<Recipients json>> <<GDrive files to search for>> <<email FROM>>");
            System.out.println("Example: java -jar gdrive-forwarder-1.0.jar credentials.json credentials2.json recipients.json owner@gmail.com from@gmail.com");
            System.exit(0);
        }
        if(args.length > 0){
            gdriveCredPath = args[0];
            gmailCredPath = args[1];
            recipients = args[2];
            owner = args[3];
            from = args[4];
        }
        Instant instant = Instant.now();
        // reference to last accessed file
        Path path = Paths.get(LAST_ACCESSED_FILE);
        String lastAccessed = readFile(path);
        LocalDateTime expiry = LocalDateTime.now().minusDays(1);
        if(lastAccessed != null) {
            expiry = Instant.ofEpochMilli(Long.parseLong(lastAccessed)).atZone(ZoneId.systemDefault()).toLocalDateTime();
        }

        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Drive driveService = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT, gdriveCredPath, GDRIVE_TOKEN_DIRECTORY_PATH, GDRIVE_SCOPES))
                .setApplicationName(APPLICATION_NAME)
                .build();

        logger.info("searching for documents after " + expiry.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")));
        // Print the names and IDs for up to 10 files.
        FileList result = driveService.files().list()
                //expiry.format(DateTimeFormatter.ofPattern(""))
                //2020-06-04T12:00:00
                .setQ("createdTime>'"+ expiry.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss")) +"' and '"+owner+"' in owners and mimeType != 'application/vnd.google-apps.folder'")
                .setOrderBy("modifiedTime desc")
                .setPageSize(10)
                .setFields("nextPageToken, files(id, name, mimeType, sharingUser, owners)")
                .execute();
        List<File> files = result.getFiles();
        if (files == null || files.isEmpty()) {
            logger.info("No files found, "); ;
        } else {

            if(!TMP_GDRIVE_FOLDER.startsWith("/tmp")) {
                throw new IllegalArgumentException("temp folder should be stored under /tmp");
            }
            Path rootPath = Paths.get(TMP_GDRIVE_FOLDER);

            // this one deletes the directory
            try (Stream<Path> walk = Files.walk(rootPath)) {
                walk.sorted(Comparator.reverseOrder())
                        .map(Path::toFile)
                        .peek(System.out::println)
                        .forEach(java.io.File::delete);
            }

            Files.createDirectories(rootPath);

            for (File file : files) {
                String exportType = null;
                String extension = file.getFileExtension();
                if(file.getMimeType().equals("application/vnd.google-apps.document")){
                    exportType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                    extension = "docx";
                } else if(file.getMimeType().equals("application/vnd.google-apps.spreadsheet")) {
                    exportType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                    extension = "xlsx";
                }

                String f = TMP_GDRIVE_FOLDER + "/" + file.getName() + "." + extension;

                try (FileOutputStream fos = new FileOutputStream(f)) {
                    if(exportType == null) {
                        driveService.files().get(file.getId()).executeMediaAndDownloadTo(fos);
                    } else {
                        driveService.files().export(file.getId(), exportType).executeMediaAndDownloadTo(fos);
                    }
                }

                // store last time there was a file that was processed
                long timeStampMillis = instant.toEpochMilli();
                //Use try-with-resource to get auto-closeable writer instance
                try (BufferedWriter writer = Files.newBufferedWriter(path))
                {
                    writer.write(String.valueOf(timeStampMillis));
                }

                logger.trace("%s (%s) %s %s %s\n", file.getName(), file.getId(),file.getMimeType(), file.getSharingUser(), file.getOwners());
            }

            // files are downloaded, now email them
            emailFiles(gmailCredPath, recipients, from);
        }
    }

    private static String readFile(Path path) {
        try {
            StringBuffer buffer = new StringBuffer();
            Files.lines(path).forEach(buffer::append);
            return buffer.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void emailFiles(String gmailCredPath, String recipients, String from) throws GeneralSecurityException, IOException {
        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        Gmail gmailService = new Gmail.Builder(HTTP_TRANSPORT, JSON_FACTORY, getCredentials(HTTP_TRANSPORT, gmailCredPath, GMAIL_TOKEN_DIRECTORY_PATH, GMAIL_SCOPES))
                .setApplicationName(APPLICATION_NAME + "2")
                .build();
        try {
            MimeMessage message = createEmailWithAttachment(getJsonRecipients(recipients), from, "Reviewers", "for issues, email richard.t.ngo@gmail.com");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            message.writeTo(baos);
            AbstractInputStreamContent mediaContent = new ByteArrayContent("message/rfc822", baos.toByteArray());
            gmailService.users().messages().send("me", null, mediaContent).execute();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }


    /**
     * Create a MimeMessage using the parameters provided.
     *
     * @param to Email address of the receiver.
     * @param from Email address of the sender, the mailbox account.
     * @param subject Subject of the email.
     * @param bodyText Body text of the email.
     * @return MimeMessage to be used to send email.
     * @throws MessagingException
     */
    public static MimeMessage createEmailWithAttachment(List<Address> to,
                                                        String from,
                                                        String subject,
                                                        String bodyText)
            throws MessagingException, IOException {
        Session session = Session.getDefaultInstance(new Properties(), null);

        MimeMessage email = new MimeMessage(session);

        email.setFrom(new InternetAddress(from));
        email.setRecipients(javax.mail.Message.RecipientType.TO,to.toArray(new Address[to.size()]));
        email.setSubject(subject);

        AtomicReference<MimeBodyPart> mimeBodyPart = new AtomicReference<>(new MimeBodyPart());
        mimeBodyPart.get().setContent(bodyText, "text/plain");

        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(mimeBodyPart.get());

        Files.list(Paths.get(TMP_GDRIVE_FOLDER))
                .filter(Files::isRegularFile)
                .forEach(file -> {
                    try{
                        mimeBodyPart.set(new MimeBodyPart());
                        FileDataSource source = new FileDataSource(file.toFile());

                        mimeBodyPart.get().setDataHandler(new DataHandler(source));
                        mimeBodyPart.get().setFileName(file.toFile().getName());

                        multipart.addBodyPart(mimeBodyPart.get());
                    } catch (MessagingException e) {
                        e.printStackTrace();
                    }
                });
        email.setContent(multipart);
        return email;
    }

    private static List<Address> getJsonRecipients(String recipients) throws FileNotFoundException {
        JsonParser parser = new JsonParser();
        JsonElement recipientsJson = parser.parse(new InputStreamReader(new FileInputStream(recipients)));
        JsonArray toRecipientsJson = recipientsJson.getAsJsonObject().get("to").getAsJsonArray();
        List<Address> r = new ArrayList<>();
        for( JsonElement recipient: toRecipientsJson ) {
            try {
                logger.info("Adding " + recipient.getAsString() + " to recipients");
                r.add(new InternetAddress(recipient.getAsString()));
            } catch (AddressException e) {
                e.printStackTrace();
            }
        }
        return r;
    }

    /**
     * Creates an authorized Credential object.
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private static Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT, final String credetialsPath, final String tokenDirectory, List<String> scopes) throws IOException {
        // Load client secrets.
        InputStream in;
        if(credetialsPath != null) {
            in = new FileInputStream(credetialsPath);
        } else {
            throw new NullPointerException("Credentials can't be null, get it from https://console.cloud.google.com/apis/credentials OAuth 2.0 Client ID and download the json");
        }

        GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, scopes)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(tokenDirectory)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    }
}
