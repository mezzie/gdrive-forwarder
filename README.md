# gdrive-forwarder
Download a file from google drive and email them to recipients. Temporarily stores files under /tmp/gdrive

## Compile
```
./gradlew clean build jar
```

## Usage
You can use the same credentials.json file for email and google drive. Just so happens my use case required me to use a different email account.  

###Parameters:

credentials1.json - credentials for the google drive account to search for

credentials2.json - credentials for the gmail account to use for email

recipients.json - people receiving the email

owner@gmail.com - owner of the document in google drive

from@gmail.com - from email address
```
java -jar gdrive-forwarder-1.0.jar credentials1.json credentials2.json recipients.json owner@gmail.com from@gmail.com
```

## Create credentials1.json and credentials2.json
Go to https://console.cloud.google.com/apis/credentials and create an OAuth 2 Client ID and download the json.

## recipients.json

```
{
  "to": ["sample@sample.com", "sample2@sample.com"]
}
```