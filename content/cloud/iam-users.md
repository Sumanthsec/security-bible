# IAM Users & Static Credentials
Tags:

## Core


## Attack Surface

An IAM user has static credentials. A username and password combination for logging into the console, or an Access Key and Secret Access Key for API calls. Attackers just love static credentials — they are easy to accidentally expose, steal, or leak. It happens. A lot. Ask me how I know. If you dare.

An IAM user has static permissions. We try and set them for least privilege, but it turns out that ends up being the least privileges someone might ever need — not the least privileges they need at that moment.

An IAM user isn’t necessarily a person. It’s also the primary mechanism for getting API credentials to allow code or systems from outside AWS to access resources or services inside your AWS account. This means anyone cracking that external app or system can now use those credentials to do bad things.

## Audit


## My Notes
