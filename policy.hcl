policy "cis-v1.30" {
  description = "GCP CIS V1.30 Policy"
  configuration {
    provider "gcp" {
      version = ">= 0.4.0"
    }
  }

  policy "gcp-cis-section-1" {
    description = "GCP CIS Section 1"

    view "gcp_project_policy_members" {
      description = "GCP project policy members"
      query "gcp_project_policy_members_query" {
        query = file("queries/project-policy-members.sql")
      }
    }

    query "1.1" {
      description   = "GCP CIS 1.1 Ensure that corporate login credentials are used"
      expect_output = true
      query         = <<EOF
      SELECT 'needs to list folders and organizations which is currently not supported'
    EOF
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.01-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Only corporate login credentials should be used for enterprise organizations, rather than personal accounts such as Gmail.
    EOF
        description     = <<EOF
It is recommended fully-managed corporate Google accounts be used for increased visibility, auditing, and controlling access to Cloud Platform resources. Email accounts based outside of the user's organization, such as personal accounts, should not be used for business purposes.
    EOF
        recommendations = <<EOF
Use only fully-managed corporate Google accounts to log into enterprise organizations.
    EOF
        references      = <<EOF
- https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_corporate_login_credentials
    EOF
        source          = "mage"
      }
    }

    query "1.2" {
      description   = "GCP CIS 1.2 Ensure that multi-factor authentication is enabled for all non-service accounts (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.02-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Multi-factor authentication requires more than one mechanism to authenticate a user. This secures your logins from attackers exploiting stolen or weak credentials.
    EOF
        description     = <<EOF
Multi-factor authentication requires more than one mechanism to authenticate a user. This secures your logins from attackers exploiting stolen or weak credentials.
    EOF
        recommendations = <<EOF
Setup multi-factor authentication for Google Cloud Platform accounts.
    EOF
        references      = <<EOF
- https://cloud.google.com/solutions/securing-gcp-account-u2f
    EOF
        source          = "mage"
      }
    }

    query "1.3" {
      description   = "GCP CIS 1.3 Ensure that Security Key Enforcement is enabled for all admin accounts (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.03-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Google Cloud Platform users with Organization Administrator roles have the highest level of privilege in the organization. These accounts should be protected with the strongest form of two-factor authentication: Security Key Enforcement.
    EOF
        description     = <<EOF
Google Cloud Platform users with Organization Administrator roles have the highest level of privilege in the organization. These accounts should be protected with the strongest form of two-factor authentication: Security Key Enforcement. Ensure that admins use Security Keys to log in instead of weaker second factors like SMS or one-time passwords (OTP). Security Keys are actual physical keys used to access Google Organization Administrator Accounts. They send an encrypted signature rather than a code, ensuring that logins cannot be phished.
    EOF
        recommendations = <<EOF
Ensure that Security Key Enforcement is enabled for all admin accounts
    EOF
        references      = <<EOF
- https://cloud.google.com/security-key/
    EOF
        source          = "mage"
      }
    }

    query "1.4" {
      description = "GCP CIS 1.4 Ensure that there are only GCP-managed service account keys for each service account"
      query       = <<EOF
      SELECT project_id , gisa."name" AS "account_name", gisak.name AS "key_name", gisak."key_type"
      FROM gcp_iam_service_accounts gisa
      JOIN gcp_iam_service_account_keys gisak ON
      gisa.cq_id = gisak.service_account_cq_id
      WHERE gisa.email LIKE '%iam.gserviceaccount.com'
      AND gisak."key_type" = 'USER_MANAGED';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
User managed service account should not have user managed keys.
    EOF
        description     = <<EOF
Anyone who has access to the keys will be able to access resources through the service account. GCP-managed keys are used by Cloud Platform services such as App Engine and Compute Engine. These keys cannot be downloaded. Google will keep the keys and automatically rotate them on an approximately weekly basis. User-managed keys are created, downloadable, and managed by users. By default, they expire 10 years from creation.
For user-managed keys, users have to take ownership of key management activities which includes:

- Key storage
- Key distribution
- Key revocation
- Key rotation
- Protecting the keys from unauthorized users
- Key recovery

Keys can be easily leaked by common development malpractices like checking keys into the source code or leaving them in Downloads directory, or accidentally leaving them on support blogs/channels. It is recommended to prevent the use of User-managed service account keys.
    EOF
        recommendations = <<EOF
Where applicable, prevent the use of User-managed service account keys.
    EOF
        references      = <<EOF
- https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys
    EOF
        source          = "mage"
      }
    }

    query "1.5" {
      description = "GCP CIS 1.5 Ensure that Service Account has no Admin privileges"
      query       = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE ("role" IN ( 'roles/editor', 'roles/owner')
          OR "role" LIKE ANY (ARRAY['%Admin', '%admin']))
      AND "member" LIKE 'serviceAccount:%';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
A service account is a special Google account that belongs to your application or a VM, instead of to an individual end user. Your application uses the service account to call the Google API of a service, so that the users aren't directly involved. It's recommended not to apply admin access to service accounts.
    EOF
        description     = <<EOF
Service accounts represent service-level security of the Resources (application or a VM) which can be determined by the roles assigned to it. Applying admin rights to a service account gives full access to assigned application or a VM, the access holder can perform critical actions like delete, update change settings etc. without the intervention of user.
This recommendation is only applicable for User-Managed user created service account (Service account with nomenclature: SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com).
    EOF
        recommendations = <<EOF
Where applicable, prevent the use of administrative service accounts.
    EOF
        references      = <<EOF
- https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/
- https://cloud.google.com/iam/docs/understanding-roles
- https://cloud.google.com/iam/docs/understanding-service-accounts
    EOF
        source          = "mage"
      }
    }

    query "1.6" {
      description = "GCP CIS 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level"
      query       = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE "role" IN ( 'roles/iam.serviceAccountUser', 'roles/iam.serviceAccountTokenCreator')
      AND "member" LIKE 'user:%';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to assign a Service Account User (iam.serviceAccountUser) role to a user for a specific service account rather than assigning the role to a user at project level.
    EOF
        description     = <<EOF
A service account is a special Google account that belongs to application or a virtual machine (VM), instead of to an individual end user. Application/VM-Instance uses the service account to call the Google API of a service, so that the users aren't directly involved.  In addition to being an identity, a service account is a resource which has IAM policies attached to it. These policies determine who can use the service account.

Users with IAM roles to update the App Engine and Compute Engine instances (such as App Engine Deployer or Compute Instance Admin) can effectively run code as the service accounts used to run these instances, and indirectly gain access to all the resources for which the service accounts has access. Similarly, SSH access to a Compute Engine instance may also provide the ability to execute code as that instance/Service account.

As per business needs, there could be multiple user-managed service accounts configured for a project. Granting the iam.serviceAccountUser role to a user for a project gives the user access to all service accounts in the project, including service accounts that may be created in the future. This can result into elevation of privileges by using service accounts and corresponding Compute Engine instances.

In order to implement least privileges best practices, IAM users should not be assigned Service Account User role at project level. Instead iam.serviceAccountUser role should be assigned to a user for a specific service account giving a user access to the service account.
    EOF
        recommendations = <<EOF
Assign a Service Account User (iam.serviceAccountUser) role to a user for a specific service account rather than assigning the role to a user at project level.
    EOF
        references      = <<EOF
- https://cloud.google.com/iam/docs/service-accounts
- https://cloud.google.com/iam/docs/granting-roles-to-service-accounts
- https://cloud.google.com/iam/docs/understanding-roles
- https://cloud.google.com/iam/docs/granting-changing-revoking-access
    EOF
        source          = "mage"
      }
    }

    query "1.7" {
      description = "GCP CIS 1.7 Ensure user-managed/external keys for service accounts are rotated every 90 days or less"
      query       = <<EOF
      SELECT project_id , gisa.id AS "account_id", gisak.name AS "key_name", gisak.valid_after_time
      FROM gcp_iam_service_accounts gisa
      JOIN gcp_iam_service_account_keys gisak ON
      gisa.cq_id = gisak.service_account_cq_id
      WHERE gisa.email LIKE '%iam.gserviceaccount.com'
      AND gisak.valid_after_time <= (now() - interval '90' day)
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Service Account keys consist of a key ID (Private_key_Id) and Private key, which are used to sign programmatic requests that you make to Google cloud services accessible to that particular Service account. It is recommended that all Service Account keys are regularly rotated.
    EOF
        description     = <<EOF
Rotating Service Account keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used. Service Account keys should be rotated to ensure that data cannot be accessed with an old key which might have been lost, cracked, or stolen.

Each service account is associated with a key pair, which is managed by Google Cloud Platform (GCP). It is used for service-to-service authentication within GCP. Google rotates the keys daily.

GCP provides option to create one or more user-managed (also called as external key pairs) key pairs for use from outside GCP (for example, for use with Application Default Credentials). When a new key pair is created, user is enforced download the private key (which is not retained by Google). With external keys, users are responsible for security of the private key and other management operations such as key rotation. External keys can be managed by the IAM API, gcloud command-line tool, or the Service Accounts page in the Google Cloud Platform Console. GCP can mint up to 10 external service account keys per service account to facilitate key rotation.
    EOF
        recommendations = <<EOF
Rotate service account keys on a regular basis
    EOF
        references      = <<EOF
- https://cloud.google.com/iam/docs/understanding-service-accounts#managing_service_account_keys
- https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/keys/list
- https://cloud.google.com/iam/docs/service-accounts
    EOF
        source          = "mage"
      }
    }

    query "1.8" {
      description = "GCP CIS 1.8 Ensure that Separation of duties is enforced while assigning service account related roles to users (Manual)"
      query       = <<EOF
      SELECT project_id , "role", "member"
      FROM gcp_project_policy_members
      WHERE "role" IN ( 'roles/iam.serviceAccountAdmin', 'roles/iam.serviceAccountUser')
      AND "member" LIKE 'user:%';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that the principle of 'Separation of Duties' is enforced while assigning service account related roles to users
    EOF
        description     = <<EOF
Built-in/Predefined IAM role Service Account admin allows user/identity to create, delete, manage service account(s). Built-in/Predefined IAM role Service Account User allows user/identity (with adequate privileges on Compute and App Engine) to assign service account(s) to Apps/Compute Instances.

Separation of duties is the concept of ensuring that one individual does not have all necessary permissions to be able to complete a malicious action. In Cloud IAM - service accounts, this could be an action such as using a service account to access resources that user should not normally have access to. Separation of duties is a business control typically used in larger organizations, meant to help avoid security or privacy incidents and errors.  It is considered best practice.

Any user(s) should not have the Service Account Admin and Service Account User roles assigned at the same time.
    EOF
        recommendations = <<EOF
Any user(s) should not have the Service Account Admin and Service Account User roles assigned at the same time.
    EOF
        references      = <<EOF
- https://cloud.google.com/iam/docs/service-accounts
- https://cloud.google.com/iam/docs/understanding-roles
- https://cloud.google.com/iam/docs/granting-roles-to-service-accounts
    EOF
        source          = "mage"
      }
    }

    query "1.9" {
      description = "GCP CIS 1.9 Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible"
      query       = <<EOF
        SELECT project_id , "role", "member"
        FROM gcp_project_policy_members
        WHERE "member" LIKE '%allUsers%'
        OR "member" LIKE '%allAuthenticatedUsers%';
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that the IAM policy on Cloud KMS cryptokeys should restrict anonymous and/or public access.
    EOF
        description     = <<EOF
Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is stored at the location. In this case, ensure that anonymous and/or public access to a Cloud KMS cryptokey is not allowed.
    EOF
        recommendations = <<EOF
Restrict Cloud KMS cryptokeys access only to those that need it
    EOF
        references      = <<EOF
- https://cloud.google.com/kms/docs/key-rotation#frequency_of_key_rotation
    EOF
        source          = "mage"
      }
    }

    query "1.10" {
      description = "GCP CIS 1.10 Ensure KMS encryption keys are rotated within a period of 90 days"
      query       = <<EOF
        SELECT *
        FROM gcp_kms_keyring_crypto_keys gkkck
        WHERE (rotation_period LIKE '%s'
            AND REPLACE(rotation_period, 's', '')::NUMERIC > 7776000)
        OR (rotation_period LIKE '%h'
            AND REPLACE(rotation_period, 'h', '')::NUMERIC > 2160)
        OR (rotation_period LIKE '%m'
            AND REPLACE(rotation_period, 'm', '')::NUMERIC > 129600)
        OR (rotation_period LIKE '%d'
            AND REPLACE(rotation_period, 'd', '')::NUMERIC > 90)
        OR DATE_PART('day', CURRENT_DATE - next_rotation_time ) > 90 ;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Google Cloud Key Management Service (KMS) stores cryptographic keys in a hierarchical structure designed for useful and elegant access control management.

Automatic cryptographic key rotation is only available for symmetric keys. Cloud KMS does not support automatic rotation of asymmetric keys so such keys are out of scope for this control. More information can be found in the GCP documentation references of this control.
    EOF
        description     = <<EOF
Google Cloud Key Management Service (KMS) stores cryptographic keys in a hierarchical structure designed for useful and elegant access control management. It is recommended to rotate these keys on a regular interval. A KMS key can be created with a specified rotation period, which is the time between when new key versions are generated automatically. A key can also be created with a specified next rotation time. The key material changes over time as new versions are created.
    EOF
        recommendations = <<EOF
Where applicable, set a key rotation period and starting time
    EOF
        references      = <<EOF
- https://cloud.google.com/kms/docs/key-rotation#frequency_of_key_rotation
- https://cloud.google.com/kms/docs/key-rotation#asymmetric
    EOF
        source          = "mage"
      }
    }

    query "1.11" {
      description = "GCP CIS 1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users"
      query       = <<EOF
        SELECT project_id , "role", "member"
        FROM gcp_project_policy_members
        WHERE "role" = 'cloudkms.admin'
        AND "member" LIKE 'user:%';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The built-in/predefined IAM role Cloud KMS Admin allows the user/identity to create, delete, and manage service account(s). It is recommended that the principle of 'Separation of Duties' is enforced while assigning KMS related roles to users.
    EOF
        description     = <<EOF
The built-in/predefined IAM role Cloud KMS Admin allows the user/identity to create, delete, and manage service account(s). Built-in/Predefined IAM role Cloud KMS CryptoKey Encrypter/Decrypter allows the user/identity to encrypt and decrypt data at rest using encryption key(s).

Separation of duties is the concept of ensuring that one individual does not have all necessary permissions to be able to complete a malicious action.

Any user(s) should not have Cloud KMS Admin and any of the Cloud KMS CryptoKey Encrypter/Decrypter, Cloud KMS CryptoKey Encrypter, Cloud KMS CryptoKey Decrypter roles assigned at the same time.
    EOF
        recommendations = <<EOF
Where applicable, separate users who have the Cloud KMS Admin role and users who have the KMS Encrypter or Decrypter roles
    EOF
        references      = <<EOF
- https://cloud.google.com/kms/docs/separation-of-duties
    EOF
        source          = "mage"
      }
    }

    query "1.12" {
      description   = "GCP CIS 1.12 Ensure API keys are not created for a project (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.12-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. Where possible, it is recommended to use the standard authentication flow instead.
    EOF
        description     = <<EOF
Security risks involved in using API-Keys are below:

- API keys are simple encrypted strings
- API keys do not identify the user or the application making the API request (they do not have a principle)
- API keys are typically accessible to clients, making it easy to discover and steal an API key

To avoid security risk by using API keys, where possible, it is recommended to use standard authentication flow instead.
    EOF
        recommendations = <<EOF
Where applicable, use the standard authentication flows to identify users making requests
    EOF
        references      = <<EOF
- https://cloud.google.com/docs/authentication/api-keys
    EOF
        source          = "mage"
      }
    }
    query "1.13" {
      description   = "GCP CIS 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.13-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key usage only from trusted hosts and apps.
    EOF
        description     = <<EOF
Security risks involved in using API-Keys are below:

- API keys are simple encrypted strings
- API keys do not identify the user or the application making the API request
- API keys are typically accessible to clients, making it easy to discover and steal an API key

Because of this Google recommends using the standard authentication flow instead. However, there are limited cases where API keys are appropriate. For example, if there is a mobile application that needs to use the Google Cloud Translation API, but doesn't otherwise need a back-end server, API keys are the simplest way to authenticate to that API.

In order to reduce attack surface, API-Keys can be restricted only to the trusted hosts and applications.
    EOF
        recommendations = <<EOF
Where applicable, restrict API key access to trusted hosts and applications
    EOF
        references      = <<EOF
- https://cloud.google.com/docs/authentication/api-keys
    EOF
        source          = "mage"
      }
    }

    query "1.14" {
      description   = "GCP CIS 1.14 Ensure API keys are restricted to only APIs that application needs access (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.14-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to restrict API key permissions to only the required upstream services.
    EOF
        description     = <<EOF
Security risks involved in using API-Keys are below:

- API keys are simple encrypted strings
- API keys do not identify the user or the application making the API request
- API keys are typically accessible to clients, making it easy to discover and steal an API key

Because of this Google recommends using the standard authentication flow instead. However, there are limited cases where API keys are appropriate. For example, if there is a mobile application that needs to use the Google Cloud Translation API, but doesn't otherwise need a back-end server, API keys are the simplest way to authenticate to that API.

In order to reduce attack surface, it is recommended to restrict API key permissions to only the required upstream services.
    EOF
        recommendations = <<EOF
Where applicable, restrict API key permissions to only the required upstream services.
    EOF
        references      = <<EOF
- https://cloud.google.com/docs/authentication/api-keys
- https://cloud.google.com/apis/docs/overview
    EOF
        source          = "mage"
      }
    }

    query "1.15" {
      description   = "GCP CIS 1.15 Ensure API keys are rotated every 90 days (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/1.15-iam.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Unrestricted keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended that API keys are rotated at least every 90 days.
    EOF
        description     = <<EOF
Security risks involved in using API-Keys are below:

- API keys are simple encrypted strings
- API keys do not identify the user or the application making the API request
- API keys are typically accessible to clients, making it easy to discover and steal an API key

Because of this Google recommends using the standard authentication flow instead. However, there are limited cases where API keys are appropriate. For example, if there is a mobile application that needs to use the Google Cloud Translation API, but doesn't otherwise need a back-end server, API keys are the simplest way to authenticate to that API.

If a key is compromised, it has no expiration, so it may be used indefinitely, unless the project owner revokes or regenerates the key. Rotating API keys will reduce the window of opportunity for an access key that is associated with a compromised or terminated account to be used.
    EOF
        recommendations = <<EOF
Where applicable, rotate API keys at least every 90 days
    EOF
        references      = <<EOF
- https://cloud.google.com/docs/authentication/api-keys
- https://cloud.google.com/apis/docs/overview
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-2" {
    description = "GCP CIS Section 2"

    view "gcp_log_metric_filters" {
      description = "GCP Log Metric Filter and Alarm"
      query "gcp_log_metric_filters_query" {
        query = file("queries/log-metric-filters.sql")
      }
    }

    query "2.1" {
      description = "GCP CIS 2.1 Ensure that Cloud Audit Logging is configured properly across all services and all users from a project"
      query       = <<EOF
        WITH project_policy_audit_configs AS ( SELECT project_id, jsonb_array_elements(p.policy -> 'auditConfigs') AS audit_config
        FROM gcp_resource_manager_projects p ), log_types AS (SELECT project_id, audit_config ->> 'service' AS "service", jsonb_array_elements(audit_config -> 'auditLogConfigs') ->> 'logType' AS logs, jsonb_array_elements(audit_config -> 'auditLogConfigs') ->> 'exemptedMembers' AS exempted
        FROM project_policy_audit_configs) SELECT project_id, service , count(*)
        FROM log_types
        WHERE exempted IS NULL
        AND logs IN ('DATA_READ', 'DATA_WRITE')
        AND service = 'allServices'
        GROUP BY project_id, service
        --count(*) > 2 means DATA_READ and DATA_WRITE are there
        HAVING count(*) = 2;
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that Cloud Audit Logging is configured to track all Admin activities and read, write access to user data.
    EOF
        description     = <<EOF
Cloud Audit Logging maintains two audit logs for each project and organization: Admin Activity and Data Access.

1. Admin Activity logs contain log entries for API calls or other administrative actions that modify the configuratin or metadata of resources. Admin Activity audit logs are enabled for all services and cannot be configured.
2. Data Access audit logs record API calls that create, modify, or read user-provided data. These are disabled by default and should be enabled. There are three kinds of Data Access audit log information:

   - Admin read: Records operations that read metadata or configuration information. Admin Activity audit logs record writes of metadata and configuration information which cannot be disabled.
   - Data read: Records operations that read user-provided data.
   - Data write: Records operations that write user-provided data.

It is recommended to have effective default audit config configured in such a way that:

1. logtype is set to DATA_READ (to logs user activity tracking) and DATA_WRITES (to log changes/tampering to user data)
2. audit config is enabled for all the services supported by Data Access audit logs feature
3. Logs should be captured for all users. i.e. there are no exempted users in any of the audit config section. This will ensure overriding audit config will not contradict the requirement.
    EOF
        recommendations = <<EOF
Configure Cloud Audit Logging to properly track admin activities and read or write access to user data.
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/audit/
- https://cloud.google.com/logging/docs/audit/configure-data-access
    EOF
        source          = "mage"
      }
    }

    query "2.2" {
      description = "GCP CIS 2.2 Ensure that sinks are configured for all log entries"
      query       = <<EOF
        WITH found_sinks AS (SELECT count(*) AS configured_sinks
        FROM gcp_logging_sinks gls
        WHERE gls.FILTER = '') SELECT 'no sinks for all log entries configured' AS description
        FROM found_sinks
        WHERE configured_sinks = 0;
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to create sinks which will export copies of all the log entries.
    EOF
        description     = <<EOF
Log entries are held in Stackdriver Logging for a limited time known as the retention period. After that, the entries are deleted. To keep log entries longer, sinks can export them outside of Stackdriver Logging. Exporting involves writing a filter that selects the log entries to export, and choosing a destination in Cloud Storage, BigQuery, or Cloud Pub/Sub.
    EOF
        recommendations = <<EOF
Configure sinks for all log entries
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/logging/quotas
- https://cloud.google.com/logging/docs/export/
- https://cloud.google.com/logging/docs/export/using_exported_logs
- https://cloud.google.com/logging/docs/export/configure_export_v2
    EOF
        source          = "mage"
      }
    }

    query "2.3" {
      description = "GCP CIS 2.3 Ensure that retention policies on log buckets are configured using Bucket Lock"
      query       = <<EOF
        SELECT gls.project_id, gls.name AS "sink_name", gsb.name AS "bucket_name", gsb.retention_policy_is_locked, gsb.retention_policy_retention_period, gls.destination
        FROM gcp_logging_sinks gls
        JOIN gcp_storage_buckets gsb ON
        gsb.name = REPLACE (gls.destination, 'storage.googleapis.com/', '')
        WHERE gls.destination LIKE 'storage.googleapis.com/%'
        AND ( gsb.retention_policy_is_locked = FALSE
        OR gsb.retention_policy_retention_period = 0)
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set up retention policies and configure Bucket Lock on all storage buckets that are used as log sinks.
    EOF
        description     = <<EOF
Logs can be exported by creating one or more sinks that include a log filter and a destination. As Stackdriver Logging receives new log entries, they are compared against each sink. If a log entry matches a sink's filter, then a copy of the log entry is written to the destination.

Sinks can be configured to export logs in storage buckets. It is recommended to configure a data retention policy for these cloud storage buckets and to lock the data retention policy; thus permanently preventing the policy from being reduced or removed. This way, if the system is ever compromised by an attacker or a malicious insider who wants to cover their tracks, the activity logs are definitely preserved for forensics and security investigations.
    EOF
        recommendations = <<EOF
Configure retention policies on log buckets using Bucket Lock
    EOF
        references      = <<EOF
- https://cloud.google.com/storage/docs/bucket-lock
    EOF
        source          = "mage"
      }
    }

    query "2.4" {
      description   = "GCP CIS 2.4 Ensure log metric filter and alerts exist for project ownership assignments/changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*(\s*protoPayload.serviceName\s*=\s*"cloudresourcemanager.googleapis.com"\s*)\s*AND\s*(\s*ProjectOwnership\s*OR\s*projectOwnerInvitee\s*)\s*OR\s*(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"REMOVE"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*)\s*OR\s*(\s*protoPayload.serviceData.policyDelta.bindingDeltas.action\s*=\s*"ADD"\s*AND\s*protoPayload.serviceData.policyDelta.bindingDeltas.role\s*=\s*"roles/owner"\s*)\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
In order to prevent unnecessarily project ownership assignments to users/serviceaccounts and further misuses of project and resources, all roles/Owner assignments should be monitored.
    EOF
        description     = <<EOF
Members (users/Service-Accounts) with the owner role are considered Project Owners.

Project Owners have all the privileges on a project it belongs to. These can be summarized as below:

- All viewer permissions on All GCP Services part within the project
- Permissions for actions that modify state of All GCP Services within the
project
- Manage roles and permissions for a project and all resources within the
project
- Set up billing for a project

Granting owner role to a member (user/Service-Account) will allow members to modify the IAM policy. Ensuring a log metrics filter exists for these changes will help monitor for excessive privileges and account abuse.
    EOF
        recommendations = <<EOF
Configure logging for project ownership assignments and changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
    EOF
        source          = "mage"
      }
    }

    query "2.5" {
      description   = "GCP CIS 2.5 Ensure that the log metric filter and alerts exist for Audit Configuration changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*protoPayload.methodName\s*=\s*"SetIamPolicy"\s*AND\s*protoPayload.serviceData.policyDelta.auditConfigDeltas:*\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Cloud Audit logging records information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the GCP services. It also provides a history of AWS API calls for an account, including API calls made via the Console, SDKs, command line tools, and other GCP services.
    EOF
        description     = <<EOF
Admin activity and Data access logs produced by Cloud audit logging enables security analysis, resource change tracking, and compliance auditing. It is recommended to configure metric filters and alerts to log audit configuration events.
    EOF
        recommendations = <<EOF
Configure logging for audit configuration changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/logging/docs/audit/configure-data-access#getiampolicy-setiampolicy
    EOF
        source          = "mage"
      }
    }

    query "2.6" {
      description   = "GCP CIS 2.6 Ensure that the log metric filter and alerts exist for Custom Role changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*"iam_role"\s*AND\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.CreateRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.DeleteRole"\s*OR\s*protoPayload.methodName\s*=\s*"google.iam.admin.v1.UpdateRole"\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for changes IAM Role creation, deletion and updating activities.
    EOF
        description     = <<EOF
Google Cloud Identity and Access Management (Cloud IAM) provides predefined roles that give granular access to specific Google Cloud Platform resources and prevent unwanted access to other resources.

To cater organization-specific needs, Cloud IAM also provides ability to create custom roles. Project Owner and administrators with Organization Role Administrator role or the IAM Role Administrator role can create custom roles. Monitoring role creation, deletion and updating activities will help in identifying over-privileged roles at early stages.
    EOF
        recommendations = <<EOF
Configure logging for custom role changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/iam/docs/understanding-custom-roles
    EOF
        source          = "mage"
      }
    }

    query "2.7" {
      description   = "GCP CIS 2.7 Ensure that the log metric filter and alerts exist for VPC Network Firewall rule changes"
      expect_output = true
      query         = <<EOF
          SELECT * FROM gcp_log_metric_filters WHERE
          enabled = TRUE
          AND "filter" ~ '\s*resource.type\s*=\s*"gce_firewall_rule"\s*AND\s*protoPayload.methodName\s*=\s*"v1.compute.firewalls.patch"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.firewalls.insert"\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for VPC Network Firewall rule changes.
    EOF
        description     = <<EOF
Monitoring for Create or Update firewall rule events gives insight to network access changes and may reduce the time it takes to detect suspicious activity.
    EOF
        recommendations = <<EOF
Configure logging for VPC Network Firewall rule changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/vpc/docs/firewalls
    EOF
        source          = "mage"
      }
    }

    query "2.8" {
      description   = "GCP CIS 2.8 Ensure that the log metric filter and alerts exist for VPC network route changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*"gce_route"\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.routes.patch"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.routes.insert"\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for VPC network route changes.
    EOF
        description     = <<EOF
Google Cloud Platform VPC routes define the paths network traffic takes from a GCP-supported source to other destinations. Monitoring VPC network route changes can help detect malicious entries intended to provide attackers with additional access.
    EOF
        recommendations = <<EOF
Configure logging for VPC Network route changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/storage/docs/access-control/iam
    EOF
        source          = "mage"
      }
    }

    query "2.9" {
      description   = "GCP CIS 2.9 Ensure that the log metric filter and alerts exist for VPC network changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*gce_network\s*AND\s*protoPayload.methodName\s*=\s*"beta.compute.networks.insert"\s*OR\s*protoPayload.methodName\s*=\s*"beta.compute.networks.patch"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.delete"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.removePeering"\s*OR\s*protoPayload.methodName\s*=\s*"v1.compute.networks.addPeering"\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for VPC network changes.
    EOF
        description     = <<EOF
Google Cloud Platform VPC networks take two or more VPC sources and connect them together. Monitoring VPC network changes can help detect malicious entries intended to provide attackers with additional access.
    EOF
        recommendations = <<EOF
Configure logging for VPC Network changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/vpc/docs/overview
    EOF
        source          = "mage"
      }
    }

    query "2.10" {
      description   = "GCP CIS 2.10 Ensure that the log metric filter and alerts exist for Cloud Storage IAM permission changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" ~ '\s*resource.type\s*=\s*gcs_bucket\s*AND\s*protoPayload.methodName\s*=\s*"storage.setIamPermissions"\s*';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for Cloud Storage Bucket IAM changes.
    EOF
        description     = <<EOF
Monitoring changes to Cloud Storage bucket permissions may reduce time to detect and correct permissions on sensitive Cloud Storage bucket and objects inside the bucket.
    EOF
        recommendations = <<EOF
Configure logging for Cloud Storage IAM permission changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/storage/docs/access-control/iam-roles
    EOF
        source          = "mage"
      }
    }

    query "2.11" {
      description   = "GCP CIS 2.11 Ensure that the log metric filter and alerts exist for SQL instance configuration changes"
      expect_output = true
      query         = <<EOF
        SELECT * FROM gcp_log_metric_filters WHERE
        enabled = TRUE
        AND "filter" = 'protoPayload.methodName="cloudsql.instances.update"';
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that a metric filter and alarm be established for SQL Instance configuration changes.
    EOF
        description     = <<EOF
Monitoring changes to SQL instance configuration permissions may reduce time to detect and correct changes made to SQL instances.
    EOF
        recommendations = <<EOF
Configure logging for SQL instance configuration changes
    EOF
        references      = <<EOF
- https://cloud.google.com/logging/docs/logs-based-metrics/
- https://cloud.google.com/monitoring/custom-metrics/
- https://cloud.google.com/monitoring/alerts/
- https://cloud.google.com/logging/docs/reference/tools/gcloud-logging
- https://cloud.google.com/sql/docs/
- https://cloud.google.com/sql/docs/mysql/
- https://cloud.google.com/sql/docs/postgres/
    EOF
        source          = "mage"
      }
    }

    query "2.12" {
      description = "GCP CIS 2.12 Ensure that Cloud DNS logging is enabled for all VPC networks"
      query       = <<EOF
        SELECT gcn.id, gcn.project_id , gcn.name AS network_name, gcn.self_link as network_link, gdp.name AS policy_network_name
        FROM gcp_compute_networks gcn
        JOIN gcp_dns_policy_networks gdpn ON
        gcn.self_link = REPLACE(gdpn.network_url, 'compute.googleapis', 'www.googleapis')
        JOIN gcp_dns_policies gdp ON
        gdp.id = gdpn.policy_id
        WHERE gdp.enable_logging = FALSE;
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that Cloud DNS Logging be enabled for all VPC networks.
    EOF
        description     = <<EOF
Cloud DNS logging tracks queries that name servers resolve for your Virtual Private Cloud (VPC) networks. Queries from an external entity directly to a public zone are not logged because a public name server handles them.

This provides valuable insight into forwarding, propagation, and resolution, which is extremely useful during investigation and troubleshooting.
    EOF
        recommendations = <<EOF
Configure Cloud DNS logging for all VPC networks
    EOF
        references      = <<EOF
- https://cloud.google.com/dns/docs/monitoring
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-3" {
    description = "GCP CIS Section 3"

    view "gcp_firewall_allowed_rules" {
      description = "firewall allowed rules port ranges dissasembled"
      query "gcp_firewall_allowed_rules" {
        query = file("queries/firewall-allowed-view.sql")
      }
    }

    query "3.1" {
      description = "GCP CIS 3.1 Ensure that the default network does not exist in a project"
      query       = <<EOF
        SELECT project_id, id, "name", self_link as link
        FROM gcp_compute_networks gcn
        WHERE name = 'default';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that the default network be removed from new projects.
    EOF
        description     = <<EOF
The default network has automatically created firewall rules and has pre-fabricated network configuration. Based on security and networking requirements, organizations should create customized networks and delete the default one.
    EOF
        recommendations = <<EOF
Remove the default network from new projects
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/networking#firewall_rules
- https://cloud.google.com/compute/docs/reference/latest/networks/insert
- https://cloud.google.com/compute/docs/reference/latest/networks/delete
    EOF
        source          = "mage"
      }
    }

    query "3.2" {
      description = "GCP CIS 3.2 Ensure legacy networks do not exist for a project"
      query       = <<EOF
        SELECT gdmz.project_id, gdmz.id, gdmz.name, gdmz.dns_name 
        FROM gcp_dns_managed_zones gdmz
        WHERE gdmz.dnssec_config_state != 'on'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that any legacy networks be removed from existing projects.
    EOF
        description     = <<EOF
Legacy networks have a single network IPv4 prefix range and gateway IP address for the whole network. The network is global in scope and spans all cloud regions. You cannot create subnetworks in a legacy network or switch from legacy to auto or custom subnet networks. Legacy networks can thus have an impact for high network traffic projects and are subject to a single point of contention or failure.
    EOF
        recommendations = <<EOF
Remove the default network from new projects
    EOF
        references      = <<EOF
- https://cloud.google.com/vpc/docs/legacy
- https://cloud.google.com/vpc/docs/legacy#replacing-legacy
    EOF
        source          = "mage"
      }
    }

    query "3.3" {
      description = "GCP CIS 3.3 Ensure that DNSSEC is enabled for Cloud DNS"
      query       = <<EOF
        SELECT project_id, id, "name", self_link as link
        FROM gcp_compute_networks gcn
        WHERE ip_v4_range IS NULL
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Cloud DNS is a fast, reliable and cost-effective Domain Name System that powers millions of domains on the internet. DNSSEC in Cloud DNS enables domain owners to take easy steps to protect their domains against DNS hijacking, man-in-the-middle, and other attacks.
    EOF
        description     = <<EOF
Domain Name System Security Extensions (DNSSEC) adds security to the Domain Name System (DNS) protocol by enabling DNS response validation. Without DNSSEC, attackers can hijack the resolution process and redirect users to malicious sites. DNSSEC helps mitigate the risk of such attacks by cryptographically signing DNS records.
    EOF
        recommendations = <<EOF
Configure DNSSEC for Cloud DNS
    EOF
        references      = <<EOF
- https://cloud.google.com/dns/dnssec-config#enabling'
- https://cloud.google.com/dns/dnssec
    EOF
        source          = "mage"
      }
    }

    query "3.4" {
      description = "GCP CIS 3.4 Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC"
      query       = <<EOF
        SELECT  gdmz.project_id, gdmz.id, gdmz.name, gdmz.dns_name , gdmzdcdks."key_type" , gdmzdcdks.algorithm
        FROM gcp_dns_managed_zones gdmz
        JOIN gcp_dns_managed_zone_dnssec_config_default_key_specs gdmzdcdks ON
        gdmz.id = gdmzdcdks.managed_zone_id
        WHERE gdmzdcdks."key_type" = 'keySigning'
        AND gdmzdcdks.algorithm = 'rsasha1';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
DNSSEC algorithms in this registry may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms. The algorithm used for key signing is recommended to be as strong as possible.
    EOF
        description     = <<EOF
When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, you can select the DNSSEC signing algorithms and the denial-of-existence type. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If you need to change the settings for a managed zone where it has been enabled, you can turn DNSSEC off and then re-enable it with different settings.
    EOF
        recommendations = <<EOF
Ensure that RSASHA1 is not used for the key-signing key in Cloud DNS DNSSEC
    EOF
        references      = <<EOF
- https://cloud.google.com/dns/dnssec-advanced#advanced_signing_options
    EOF
        source          = "mage"
      }
    }

    query "3.5" {
      description = "GCP CIS 3.5 Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC"
      query       = <<EOF
        SELECT gdmz.id, gdmz.project_id, gdmz.dns_name , gdmzdcdks."key_type" , gdmzdcdks.algorithm
        FROM gcp_dns_managed_zones gdmz
        JOIN gcp_dns_managed_zone_dnssec_config_default_key_specs gdmzdcdks ON
        gdmz.id = gdmzdcdks.managed_zone_id
        WHERE gdmzdcdks."key_type" = 'zoneSigning'
        AND gdmzdcdks.algorithm = 'rsasha1'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
DNSSEC algorithms in this registry may be used in CERT RRs. Zone signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG) make use of particular subsets of these algorithms. The algorithm used for zone signing is recommended to be as strong as possible.
    EOF
        description     = <<EOF
When enabling DNSSEC for a managed zone, or creating a managed zone with DNSSEC, you can select the DNSSEC signing algorithms and the denial-of-existence type. Changing the DNSSEC settings is only effective for a managed zone if DNSSEC is not already enabled. If you need to change the settings for a managed zone where it has been enabled, you can turn DNSSEC off and then re-enable it with different settings.
    EOF
        recommendations = <<EOF
Ensure that RSASHA1 is not used for the zone-signing key in Cloud DNS DNSSEC
    EOF
        references      = <<EOF
- https://cloud.google.com/dns/dnssec-advanced#advanced_signing_options
    EOF
        source          = "mage"
      }
    }

    query "3.6" {
      description = "GCP CIS 3.6 Ensure that SSH access is restricted from the internet"
      query       = <<EOF
        SELECT *
        FROM gcp_firewall_allowed_rules
        WHERE direction = 'INGRESS'
        AND ( ip_protocol = 'tcp'
          OR ip_protocol = 'all' )
        AND '0.0.0.0/0' = ANY (source_ranges)
        AND (22 BETWEEN range_start AND range_end
          OR '22' = single_port
          OR CARDINALITY(ports) = 0
          OR ports IS NULL)
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
GCP Firewall Rules are specific to a VPC Network. Each rule either allows or denies traffic when its conditions are met. Its conditions allow you to specify the type of traffic, such as ports and protocols, and the source or destination of the traffic, including IP addresses, subnets, and instances. Firewall rules are defined at the VPC network level, and are specific to the network in which they are defined. If possible, internet traffic (0.0.0.0/0) coming into a VPC or VM instance using SSH on port 22 should be avoided.
    EOF
        description     = <<EOF
GCP Firewall rules apply to outgoing (egress) traffic and incoming (ingress) traffic. Egress and ingress traffic are controlled even if the traffic stays within the network (e.g., instance-to-instance communication). It is recommended to restrict the allowed IP range where possible, especially with management protocols such as SSH.
    EOF
        recommendations = <<EOF
Ensure that SSH access is restricted from the internet
    EOF
        references      = <<EOF
- https://cloud.google.com/vpc/docs/firewalls#blockedtraffic
    EOF
        source          = "mage"
      }
    }

    query "3.7" {
      description = "GCP CIS 3.7 Ensure that RDP access is restricted from the Internet"
      query       = <<EOF
        SELECT *
        FROM gcp_firewall_allowed_rules
        WHERE direction = 'INGRESS'
        AND ( ip_protocol = 'tcp'
          OR ip_protocol = 'all' )
        AND '0.0.0.0/0' = ANY (source_ranges)
        AND (3389 BETWEEN range_start AND range_end
          OR '3389' = single_port
          OR CARDINALITY(ports) = 0
          OR ports IS NULL)
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
GCP Firewall Rules are specific to a VPC Network. Each rule either allows or denies traffic when its conditions are met. Its conditions allow you to specify the type of traffic, such as ports and protocols, and the source or destination of the traffic, including IP addresses, subnets, and instances. Firewall rules are defined at the VPC network level, and are specific to the network in which they are defined. If possible, internet traffic (0.0.0.0/0) coming into a VPC or VM instance using RDP on port 3389 should be avoided.
    EOF
        description     = <<EOF
GCP Firewall rules apply to outgoing (egress) traffic and incoming (ingress) traffic. Egress and ingress traffic are controlled even if the traffic stays within the network (e.g., instance-to-instance communication). It is recommended to restrict the allowed IP range where possible, especially with management protocols such as SSH.
    EOF
        recommendations = <<EOF
Ensure that SSH access is restricted from the internet
    EOF
        references      = <<EOF
- https://cloud.google.com/vpc/docs/firewalls#blockedtraffic
    EOF
        source          = "mage"
      }
    }

    query "3.8" {
      description = "GCP CIS 3.8 Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network"
      query       = <<EOF
        SELECT gcn.id, gcn.project_id, gcn.self_link AS network, gcs.self_link AS subnetwork, gcs.enable_flow_logs
        FROM gcp_compute_networks gcn
        JOIN gcp_compute_subnetworks gcs ON
        gcn.self_link = gcs.network
        WHERE gcs.enable_flow_logs = FALSE;
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC Subnets. After you've created a flow log, you can view and retrieve its data in Stackdriver Logging. It is recommended that Flow Logs be enabled for every business critical VPC subnet.
    EOF
        description     = <<EOF
VPC networks and subnetworks provide logically isolated and secure network partitions where you can launch GCP resources. When Flow Logs is enabled for a subnet, VMs within subnet starts reporting on all TCP and UDP flows. Each VM samples the TCP and UDP flows it sees, inbound and outbound, whether the flow is to or from another VM, a host in your on-premises datacenter, a Google service, or a host on the Internet.

Flow Logs supports following use cases:

- Network monitoring
- Understanding network usage and optimizing network traffic expenses
- Network forensics
- Real-time security analysis

Flow Logs provide visibility into network traffic for each VM inside the subnet and can be used to detect anomalous traffic during security or troubleshooting workflows.
    EOF
        recommendations = <<EOF
Ensure that VPC Flow Logs is enabled for every subnet in a VPC Network
    EOF
        references      = <<EOF
- https://cloud.google.com/vpc/docs/using-flow-logs#enabling_vpc_flow_logging'
- https://cloud.google.com/vpc/
    EOF
        source          = "mage"
      }
    }

    query "3.9" {
      description = "GCP CIS 3.9 Ensure no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites"
      query       = <<EOF
        SELECT gctsp.id, gctsp.project_id, gctsp.name, gctsp.ssl_policy, 'wrong policy' AS reason
        FROM gcp_compute_target_https_proxies gctsp
        WHERE ssl_policy NOT LIKE 'https://www.googleapis.com/compute/v1/projects/%/global/sslPolicies/%'
        UNION ALL SELECT gctsp.id, gctsp.project_id, gctsp.name, gctsp.ssl_policy, 'insecure policy config' AS reason
        FROM gcp_compute_target_https_proxies gctsp
        JOIN gcp_compute_ssl_policies p ON
        gctsp.ssl_policy = p.self_link
        WHERE gctsp.ssl_policy LIKE 'https://www.googleapis.com/compute/v1/projects/%/global/sslPolicies/%'
        AND (p.min_tls_version != 'TLS_1_2' OR  p.min_tls_version != 'TLS_1_3')
        AND (
          (p.profile = 'MODERN' OR p.profile = 'RESTRICTED' )
          OR (p.profile = 'CUSTOM' AND ARRAY ['TLS_RSA_WITH_AES_128_GCM_SHA256' , 'TLS_RSA_WITH_AES_256_GCM_SHA384' , 'TLS_RSA_WITH_AES_128_CBC_SHA' , 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'] @> p.enabled_features )
        );
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Secure Sockets Layer (SSL) policies determine what port Transport Layer Security (TLS) features clients are permitted to use when connecting to load balancers. To prevent usage of insecure features, SSL policies should use:

(a) at least TLS 1.2 with the MODERN profile; or (b) the RESTRICTED profile, because it effectively requires clients to use TLS 1.2 regardless of the chosen minimum TLS version; or (c) a CUSTOM profile that does not support any of the following features:

TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA
    EOF
        description     = <<EOF
Load balancers are used to efficiently distribute traffic across multiple servers. Both SSL proxy and HTTPS load balancers are external load balancers, meaning they distribute traffic from the Internet to a GCP network. GCP customers can configure load balancer SSL policies with a minimum TLS version (1.0, 1.1, or 1.2) that clients can use to establish a connection, along with a profile (Compatible, Modern, Restricted, or Custom) that specifies permissible cipher suites.

To comply with users using outdated protocols, GCP load balancers can be configured to permit insecure cipher suites. In fact, the GCP default SSL policy uses a minimum TLS versionls of 1.0 and a Compatible profile, which allows the widest range of insecure cipher suites. As a result, it is easy for customers to configure a load balancer without even knowing that they are permitting outdated cipher suites.
    EOF
        recommendations = <<EOF
Ensure that no HTTPS or SSL proxy load balancers permit SSL policies with weak cipher suites
    EOF
        references      = <<EOF
- https://cloud.google.com/load-balancing/docs/use-ssl-policies
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r.pdf
    EOF
        source          = "mage"
      }
    }

    query "3.10" {
      description = "GCP CIS 3.10 Ensure Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses"
      query       = <<EOF
        SELECT gcf.project_id, gcf.id, gcf.name, gcf.self_link AS link, count(*) AS broken_rules
        FROM gcp_compute_firewalls gcf
        JOIN gcp_compute_firewall_allowed gcfa ON
        gcf.cq_id = gcfa.firewall_cq_id
        WHERE NOT ARRAY ['35.191.0.0/16', '130.211.0.0/22'] <@ gcf.source_ranges and  NOT (ip_protocol = 'tcp' and ports @> ARRAY ['80'])
        GROUP BY gcf.project_id, gcf.id
        HAVING count(*) > 0;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
IAP TCP forwarding allows you to establish an encrypted tunnel over which you can forward SSH, RDP, and other traffic to VM instances. IAP TCP forwarding also provides you fine-grained control over which users are allowed to establish tunnels and which VM instances users are allowed to connect to.

All VM instances behind an IAP should be inaccessible from the internet, as the proxy will forward connections as necessary.
    EOF
        description     = <<EOF
IAP provides a single point of control for managing user access to web applications and cloud resources. IAP can protect access to applications hosted on Google Cloud, other clouds, and on-premises. With TCP forwarding, IAP can protect SSH and RDP access to VMs hosted on Google Cloud. All VM instances behind an IAP should be inaccessible from the internet, as the proxy will forward connections as necessary.
    EOF
        recommendations = <<EOF
Ensure that Firewall Rules for instances behind Identity Aware Proxy (IAP) only allow the traffic from Google Cloud Loadbalancer (GCLB) Health Check and Proxy Addresses
    EOF
        references      = <<EOF
- https://cloud.google.com/iap/docs/concepts-overview
- https://cloud.google.com/iap/docs/using-tcp-forwarding
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-4" {
    description = "GCP CIS Section 4"

    query "4.1" {
      description = "GCP CIS 4.1 Ensure that instances are not configured to use the default service account"
      query       = <<EOF
        SELECT project_id , gci."name", gci.self_link as link
        FROM gcp_compute_instances gci
        JOIN gcp_compute_instance_service_accounts gcisa ON
        gci.id = gcisa.instance_id
        WHERE gci."name" NOT LIKE 'gke-'
        AND gcisa.email = (SELECT default_service_account
        FROM gcp_compute_projects
        WHERE project_id = gci.project_id);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
To support principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned the Compute Engine default service account
    EOF
        description     = <<EOF
The default Compute Engine service account has the Editor role on the project, which allows read and write access to most Google Cloud Services. To defend against privilege escalations following a VM compromise, it is recommended to not use the default Compute Engine service account. Instead, you should create a new service account and assign only the permissions needed by your instance.
    EOF
        recommendations = <<EOF
Ensure instances are not configured to use the default service account
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances
- https://cloud.google.com/compute/docs/access/service-accounts
    EOF
        source          = "mage"
      }
    }

    query "4.2" {
      description = "GCP CIS 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs"
      query       = <<EOF
        SELECT *
        FROM gcp_compute_instances gci
        JOIN gcp_compute_instance_service_accounts gcisa ON
        gci.id = gcisa.instance_id
        WHERE gcisa.email = (SELECT default_service_account
        FROM gcp_compute_projects
        WHERE project_id = gci.project_id)
        AND 'https://www.googleapis.com/auth/cloud-platform' = ANY (gcisa.scopes);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
To support principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned to the Compute Engine default service account scoped with full access to all Cloud APIs.
    EOF
        description     = <<EOF
Google Compute Engine provides a default service account for a instances to access necessary cloud services. This service account has almost all capabilities over all cloud services except billing. When the Compute Engine default service account is assigned to an instance it can operate in 3 scopes:

1. Allow default access: Allows only minimum access required to run an Instance (Least Privileges)
2. Allow full access to all Cloud APIs: Allow full access to all the cloud APIs/Services
3. Set access for each API: Allows Instance administrator to choose only those APIs that are needed to perform specific business functionality expected by instance

When an instance is configured with Compute Engine default service account with scope "Allow full access to all Cloud APIs", it may allow the affected account to execute unintended cloud operations.
    EOF
        recommendations = <<EOF
Ensure that instances are not configured to use the default service account with full access to all Cloud APIs
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances
- https://cloud.google.com/compute/docs/access/service-accounts
    EOF
        source          = "mage"
      }
    }

    query "4.3" {
      description = "GCP CIS 4.3 Ensure \"Block Project-wide SSH keys\" is enabled for VM instances"
      query       = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_instances
        WHERE metadata_items IS NULL OR metadata_items ->> 'block-project-ssh-keys' IS NULL
        OR metadata_items ->> 'block-project-ssh-keys' != 'true';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to issue instance-specific SSH key(s) instead of using common/shared project-wide SSH key(s).
    EOF
        description     = <<EOF
Project-wide SSH keys are stored in Compute/Project meta-data. Project wide SSH keys can be used to login into all the instances within a project. Using project-wide SSH keys poses a security risk which can impact all the instances within a project.
    EOF
        recommendations = <<EOF
Ensure that "Block Project-wide SSH keys" is enabled for VM instances
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys
    EOF
        source          = "mage"
      }
    }

    query "4.4" {
      description = "GCP CIS 4.4 Ensure oslogin is enabled for a Project"
      query       = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_projects
        WHERE common_instance_metadata_items IS NULL 
        OR common_instance_metadata_items ->> 'enable-oslogin' IS NULL
        OR common_instance_metadata_items ->> 'enable-oslogin' != 'true';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling OS login binds SSH certificates to IAM users and facilitates effective SSH certificate management.
    EOF
        description     = <<EOF
Enabling oslogin ensures that SSH keys used to connect to instances are mapped with IAM users. Revoking an IAM user will revoke all the SSH keys associated with that particular user. It facilitates centralized and automated SSH key pair management which is useful in handling cases like response to compromised SSH key pairs and/or revocation of third-party users.
    EOF
        recommendations = <<EOF
Ensure that oslogin is enabled for a Project
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/instances/managing-instance-access
- https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin
    EOF
        source          = "mage"
      }
    }

    query "4.5" {
      description = "GCP CIS 4.5 Ensure 'Enable connecting to serial ports' is not enabled for VM Instance"

      query = <<EOF
        SELECT project_id , name, self_link as link
        FROM gcp_compute_instances
        WHERE metadata_items IS NOT NULL AND 
        metadata_items ->> 'serial-port-enable' = 'true'
        OR metadata_items ->> 'serial-port-enable' = '1';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Interacting with a serial port is often referred to as the serial console, which is similar to using a terminal window, in that input and output is entirely in text mode and there is no graphical interface or mouse support.

If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. It is recommended that interactive serial console support be disabled.
    EOF
        description     = <<EOF
A virtual machine instance has four virtual serial ports. Interacting with a serial port is similar to using a terminal window, in that input and output is entirely in text mode and there is no graphical interface or mouse support.

The interactive serial console does not support IP-based access restrictions such as IP whitelists. If you enable the interactive serial console on an instance, clients can attempt to connect to that instance from any IP address. This allows anybody to connect to that instance if they know the correct SSH key, username, project ID, zone, and instance name. It is recommended that interactive serial console support be disabled.
    EOF
        recommendations = <<EOF
Ensure that 'Enable connecting to serial ports' is not enabled for VM Instance
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/instances/interacting-with-serial-console
    EOF
        source          = "mage"
      }
    }

    query "4.6" {
      description = "GCP CIS 4.6 Ensure that IP forwarding is not enabled on Instances"
      query       = <<EOF
        SELECT project_id , "name", self_link as link
        FROM gcp_compute_instances 
        WHERE can_ip_forward = TRUE;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
By default, Google Cloud performs strict source and destination checking for packets. Compute Engine cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. Similarly, GCP won't deliver a packet whose destination IP address is different than the IP address of the instance receiving the packet. Although possible, it is not recommended to use instances to help route packets via the IP Forwarding setting.
    EOF
        description     = <<EOF
Compute Engine instances cannot forward a packet unless the source IP address of the packet matches the IP address of the instance. Similarly, GCP won't deliver a packet whose destination IP address is different than the IP address of the instance receiving the packet. However, both capabilities are required if you want to use instances to help route packets. Although possible, it is not recommended to use instances to help route packets via the IP Forwarding setting.
    EOF
        recommendations = <<EOF
Ensure that IP forwarding is not enabled on Instances
    EOF
        references      = <<EOF
- https://cloud.google.com/vpc/docs/using-routes#canipforward
    EOF
        source          = "mage"
      }
    }

    query "4.7" {
      description = "GCP CIS 4.7 Ensure VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)"
      query       = <<EOF
        SELECT project_id, id, name, self_link as link
        FROM gcp_compute_disks
        WHERE disk_encryption_key_sha256 IS NULL
        OR disk_encryption_key_sha256 = ''
        OR source_image_encryption_key_kms_key_name IS NULL
        OR source_image_encryption_key_kms_key_name = '';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Customer-Supplied Encryption Keys (CSEK) are a feature in Google Cloud Storage and Google Compute Engine. If you supply your own encryption keys, Google uses your key to protect the Google-generated keys used to encrypt and decrypt your data. By default, Google Compute Engine encrypts all data at rest. However, if you wanted to control and manage this encryption yourself, you can provide your own encryption keys.
    EOF
        description     = <<EOF
If you provide your own encryption keys, Compute Engine uses your key to protect the Google-generated keys used to encrypt and decrypt your data. Only users who can provide the correct key can use resources protected by a customer-supplied encryption key.

Google does not store your keys on its servers and cannot access your protected data unless you provide the key.

At least business critical VMs should have VM disks encrypted with CSEK.
    EOF
        recommendations = <<EOF
Ensure that VM disks for critical VMs are encrypted with Customer-Supplied Encryption Keys (CSEK)
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/disks/customer-supplied-encryption#encrypt_a_new_persistent_disk_with_your_own_keys
- https://cloud.google.com/compute/docs/reference/rest/v1/disks/get
- https://cloud.google.com/compute/docs/disks/customer-supplied-encryption#key_file
    EOF
        source          = "mage"
      }
    }


    query "4.8" {
      description = "GCP CIS 4.8 Ensure Compute instances are launched with Shielded VM enabled"
      query       = <<EOF
        SELECT project_id , gci."name", gci.self_link as link
        FROM gcp_compute_instances gci
        WHERE shielded_instance_config_enable_integrity_monitoring = FALSE
        OR shielded_instance_config_enable_vtpm = FALSE;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
To defend against against advanced threats and ensure that the boot loader and firmware on your VMs are signed and untampered, it is recommended that Compute instances are launched with Shielded VM enabled.
    EOF
        description     = <<EOF
Shielded VMs are virtual machines (VMs) on Google Cloud Platform hardened by a set of security controls that help defend against rootkits and bootkits.

Shielded VM offers verifiable integrity of your Compute Engine VM instances, so you can be confident your instances haven't been compromised by boot or kernel-level malware or rootkits. Secure Boot helps ensure that the system only runs authentic software by verifying the digital signature of all boot components, and halting the boot process if signature verification fails.
    EOF
        recommendations = <<EOF
Ensure that Compute instances are launched with Shielded VM enabled
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/instances/modifying-shielded-vm
- https://cloud.google.com/shielded-vm
- https://cloud.google.com/security/shielded-cloud/shielded-vm#organization-policy-constraint
    EOF
        source          = "mage"
      }
    }

    query "4.9" {
      description = "GCP CIS 4.9 Ensure that Compute instances do not have public IP addresses"
      query       = <<EOF
        SELECT project_id , gci."id", gci.self_link AS link
        FROM gcp_compute_instances gci
        LEFT JOIN gcp_compute_instance_network_interfaces gcini ON
                gci.id = gcini.instance_id
        LEFT JOIN gcp_compute_instance_network_interface_access_configs gciniac ON
                gcini.cq_id = gciniac.instance_network_interface_cq_id
        WHERE gci."name" NOT LIKE 'gke-%'
        AND (gciniac.nat_ip IS NOT NULL
          OR gciniac.nat_ip != '')
        GROUP BY project_id , gci."id"
        HAVING count(gciniac.*) > 0;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
To reduce your attack surface Compute instances should not have public IP addresses. To minimize the instance's exposure to the internet configure instances behind load balancers.

It is recommended you ensure compute instances are not configured to have external IP addresses.
    EOF
        description     = <<EOF
To reduce your attack surface Compute instances should not have public IP addresses. VM Instances created by Google Kubernetes Engine (GKE) should be excluded.

Instead, VM instances should be configured to run behind load balancers.
    EOF
        recommendations = <<EOF
Ensure that Compute instances do not have public IP addresses
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/docs/ip-addresses
- https://cloud.google.com/compute/docs/load-balancing-and-autoscaling
    EOF
        source          = "mage"
      }
    }

    query "4.10" {
      description   = "GCP CIS 4.10 Ensure that App Engine applications enforce HTTPS connections (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Ensure that all connections made to your Google App Engine applications are using HTTPS in order to protect against eavesdropping and data exposure.
    EOF
        description     = <<EOF
Ensure that all connections made to your Google App Engine applications are using HTTPS in order to protect against eavesdropping and data exposure.

By default, the HTTPS protocol is not strictly enforced for Google App Engine applications. This means that your web application is be available over plain HTTP and any sensitive information is sent unencrypted over the network, where can be intercepted by a malicious actor performing a man-in-the-middle attack. To adhere to cloud security best practices, always configure your App Engine applications to enforce HTTPS for connections to and from your web apps. 
    EOF
        recommendations = <<EOF
Ensure that App Engine applications enforce HTTPS connections
    EOF
        references      = <<EOF
- https://cloud.google.com/appengine/docs/standard/nodejs/application-security#https_requests
    EOF
        source          = "mage"
      }
    }

    query "4.11" {
      description = "GCP CIS 4.11 Ensure that Compute instances have Confidential Computing enabled"
      query       = <<EOF
        SELECT project_id , "name", gci.self_link as link
        FROM gcp_compute_instances gci
        WHERE confidential_instance_config_enable_confidential_compute = FALSE;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Along with encryption of data in transit and at rest using customer-managed encryption keys (CMEK) and customer-supplied encryption keys (CSEK), Confidential VM adds a "third pillar" to the end-to-end encryption story by encrypting data while in use. It is recommended that Compute instances have Cofidential Computing enabled where possible.
    EOF
        description     = <<EOF
Confidential VM adds a "third pillar" to the end-to-end encryption story by encrypting data while in use. Google Cloud keeps customers' sensitive code and other data encrypted in memory during processing. Google does not have access to the encryption keys.

Main memory encryption is performed using dedicated hardware within the on-die memory controllers. Each controller includes a high-performance Advanced Encryption Standard (AES) engine. The AES engine encrypts data as it is written to DRAM or shared between sockets, and decrypts it when data is read.
    EOF
        recommendations = <<EOF
Ensure that Compute instances have Confidential Computing enabled
    EOF
        references      = <<EOF
- https://cloud.google.com/compute/confidential-vm/docs/about-cvm
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-5" {
    description = "GCP CIS Section 5"

    view "gcp_public_buckets_accesses" {
      description = "Aggregated buckets and their access params"
      query "gcp_public_buckets_accesses_query" {
        query = file("queries/public-buckets-check.sql")
      }
    }

    query "5.1" {
      description = "GCP CIS 5.1 Ensure that Cloud Storage bucket is not anonymously or publicly accessible"
      query       = <<EOF
        SELECT project_id , "name", self_link as link from gcp_public_buckets_accesses
        WHERE member LIKE '%allUsers%'
        OR member LIKE '%allAuthenticatedUsers%'
        GROUP BY project_id , "name", self_link;
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that IAM policy on Cloud Storage bucket does not allows anonymous and/or public access.
    EOF
        description     = <<EOF
Allowing anonymous and/or public access grants permissions to anyone to access bucket content. Such access might not be desired if you are storing any sensitive data. When applicaable, ensure that anonymous and/or public access to a bucket is not allowed.
    EOF
        recommendations = <<EOF
Ensure that Cloud Storage bucket is not anonymously or publicly accessible
    EOF
        references      = <<EOF
- https://cloud.google.com/storage/docs/access-control/iam-reference
- https://cloud.google.com/storage/docs/access-control/making-data-public
    EOF
        source          = "mage"
      }
    }

    query "5.2" {
      description = "GCP CIS 5.2 Ensure that Cloud Storage buckets have uniform bucket-level access enabled"
      query       = <<EOF
        SELECT project_id, name, self_link as link
        FROM gcp_storage_buckets
        WHERE iam_configuration_uniform_bucket_level_access_enabled = FALSE;
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that uniform bucket-level access is enabled on Cloud Storage buckets.
    EOF
        description     = <<EOF
Cloud Storage offers two systems for granting users permission to access your buckets and objects: Cloud Identity and Access Management (Cloud IAM) and Access Control Lists (ACLs).

These systems act in parallel - in order for a user to access a Cloud Storage resource, only one of the systems needs to grant the user permission. Cloud IAM is used throughout Google Cloud and allows you to grant a variety of permissions at the bucket and project levels.

In order to support a uniform permissioning system, Cloud Storage has uniform bucket-level access. Using this feature disables ACLs for all Cloud Storage resources: access to Cloud Storage resources then is granted exclusively through Cloud IAM.

Enabling uniform bucket-level access guarantees that if a Storage bucket is not publicly accessible, no object in the bucket is publicly accessible either.
    EOF
        recommendations = <<EOF
Ensure that Cloud Storage buckets have uniform bucket-level access enabled
    EOF
        references      = <<EOF
- https://cloud.google.com/storage/docs/uniform-bucket-level-access
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-6" {
    description = "GCP CIS Section 6"

    query "6.1.1" {
      description   = "GCP CIS 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/6.01-db.rbv
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set a password for the administrative user (root by default) to prevent unauthorized access to the SQL database Instances.

This recommendation is applicable only for MySql Instances. PostgreSQL does not offer any setting for No Password from cloud console.
    EOF
        description     = <<EOF
When a MySQL instance is created, not providing a administrative password allows anyone to connect to the SQL database instance with administrative privileges. A root password should be set to ensure only authorized users have these privileges.
    EOF
        recommendations = <<EOF
Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/create-manage-users
- https://cloud.google.com/sql/docs/mysql/create-instance
    EOF
        source          = "mage"
      }
    }

    query "6.1.2" {
      description = "GCP CIS 6.1.2 Ensure 'skip_show_database' database flag for Cloud SQL Mysql instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'MYSQL%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'skip_show_database' != 'on'
            OR settings_database_flags ->> 'skip_show_database' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to enable 'skip_show_database' for Cloud MySQL instances in order to prevent exposing other databases a particular user does not have access to using the `SHOW DATABASES` command.
    EOF
        description     = <<EOF
This prevents users from using the `SHOW DATABASES` statement if they do not have the `SHOW DATABASES` privilege. This can improve security if you have concerns about users being able to see databases belonging to other users.
    EOF
        recommendations = <<EOF
Ensure that the 'skip_show_database' database flag for Cloud SQL MySQL instances is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/flags#list-flags-mysql
- https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_skip_show_database
    EOF
        source          = "mage"
      }
    }

    query "6.1.3" {
      description = "GCP CIS 6.1.3 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'MYSQL%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'local_infile' != 'off'
            OR settings_database_flags ->> 'local_infile' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set the local_infile database flag for a Cloud SQL MySQL instance to off.
    EOF
        description     = <<EOF
The `local_infile` flag controls the server-side `LOCAL` capability for `LOAD DATA` statements. Depending on the `local_infile` setting, the server refuses or permits local data loading by clients that have `LOCAL` enabled on the client side.
    EOF
        recommendations = <<EOF
Ensure that the 'skip_show_database' database flag for Cloud SQL MySQL instances is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/flags#list-flags-mysql
- https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_local_infile
    EOF
        source          = "mage"
      }
    }

    query "6.2.1" {
      description = "GCP CIS 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_checkpoints' != 'on'
            OR settings_database_flags ->> 'log_checkpoints' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling `log_checkpoints` causes checkpoints and restart points to be logged in the server log. Some statistics are included in the log messages, including the number of buffers written and the time spent writing them.
    EOF
        description     = <<EOF
Enable system logging to include detailed information such as an event source, date, user, timestamp, source addresses, destination addresses, and other useful elements.
    EOF
        recommendations = <<EOF
Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#list-flags-postgres
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
    EOF
        source          = "mage"
      }
    }

    query "6.2.2" {
      description = "GCP CIS 6.2.2 Ensure 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_error_verbosity' NOT IN('default', 'terse')
            OR settings_database_flags ->> 'log_error_verbosity' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Setting `log_error_verbosity` controls the amount of detail written in the server log for each message that is logged. Valid values are TERSE, DEFAULT, and VERBOSE. It is recommended that this value is set to DEFAULT or TERSE.
    EOF
        description     = <<EOF
If the `log_error_verbosity` setting is set to `VERBOSE`, it can disclose sensitive information to an attacker with access to the logs
    EOF
        recommendations = <<EOF
Ensure that the 'log_error_verbosity' database flag for Cloud SQL PostgreSQL instance is set to 'DEFAULT' or stricter
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#list-flags-postgres
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/current/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.3" {
      description = "GCP CIS 6.2.3 Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_connections' != 'on'
            OR settings_database_flags ->> 'log_connections' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling the log_connections setting causes each attempted connection to the server to be logged, along with successful completion of client authentication.
    EOF
        description     = <<EOF
PostgreSQL does not log attempted connections by default. Enabling the log_connections setting will create log entries for each attempted connection as well as successful completion of client authentication, which can be useful in troubleshooting issues and finding unusual connection attempts to the server.
    EOF
        recommendations = <<EOF
Ensure that the 'log_connections' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.4" {
      description = "GCP CIS 6.2.4 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_disconnections' != 'on'
            OR settings_database_flags ->> 'log_disconnections' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling the log_disconnections setting logs the end of each session, including the session duration.
    EOF
        description     = <<EOF
PostgreSQL does not log session details such as duration and session end by default. Enabling the log_disconnections setting will create log entries at the end of each session which can be useful in troubleshooting issues and finding unusual activity across a time period.
    EOF
        recommendations = <<EOF
Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.5" {
      description = "GCP CIS 6.2.5 Ensure 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_duration' != 'on'
            OR settings_database_flags ->> 'log_duration' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling the log_duration setting causes the duration of every completed statement to be logged
    EOF
        description     = <<EOF
PostgreSQL does not log statement duration by default. Enabling the log_duration setting causes the duration of every completed statement to be logged which can be useful in troubleshooting issues and finding unusual activity across a time period.
    EOF
        recommendations = <<EOF
Ensure that the 'log_duration' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.6" {
      description = "GCP CIS 6.2.6 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags IS NULL OR settings_database_flags ->> 'log_lock_waits' != 'on'
            OR settings_database_flags ->> 'log_lock_waits' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
Enabling the log_lock_waits flag for a PostgreSQL instance creates a log for any session waits that take longer than the alloted deadlock_timeout time to acquire a lock.
    EOF
        description     = <<EOF
The deadlock timeout defines the time to wait on a lock before checking for any conditions. Frequent run overs on deadlock timeout can be an indication of an underlying issue.

Enabling the log_lock_waits flag can be used to identify poor performance due to locking delays or if a specially-crafted SQL is attempting to starve resources through holding locks for excessive amounts of time.
    EOF
        recommendations = <<EOF
Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.7" {
      description   = "GCP CIS 6.2.7 Ensure 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      // TODO: Implement query, this will currently return a pass no matter what
      // https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/blob/master/controls/6.02-db.rb
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_statement flag for a PostgreSQL instance controls which SQL statements are logged.
    EOF
        description     = <<EOF
Valid values are `none` (off), `ddl`, `mod`, and `all` (all statements). `ddl` logs all data definition statements, such as CREATE, ALTER, and DROP statements. `mod` logs all ddl statements, plus data-modifying statements such as INSERT, UPDATE, DELETE, TRUNCATE, and COPY FROM. PREPARE, EXECUTE, and EXPLAIN ANALYZE statements are also logged if their contained command is of an appropriate type. It is recommended to set this according to the type of environment the instance is in.
    EOF
        recommendations = <<EOF
Ensure that the 'log_statement' database flag for Cloud SQL PostgreSQL instance is set appropriately
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.8" {
      description = "GCP CIS 6.2.8 Ensure 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set to 'on'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_hostname' != 'on'
            OR settings_database_flags ->> 'log_hostname' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_hostname flag for a PostgreSQL instance controls logging of the host name during connection
    EOF
        description     = <<EOF
By default, connection log messages only show the IP address of the connecting host. Turning this parameter on causes logging of the host name as well. Note that depending on your host name resolution setup this might impose a non-negligible performance penalty.
    EOF
        recommendations = <<EOF
Ensure the 'log_hostname' database flag for Cloud SQL PostgreSQL instance is set to 'on'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHAT
    EOF
        source          = "mage"
      }
    }

    query "6.2.9" {
      description = "GCP CIS 6.2.9 Ensure 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_parser_stats' != 'off'
            OR settings_database_flags ->> 'log_parser_stats' IS NULL);
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_parser_stats flag for a PostgreSQL instance controls the statistics monitoring for each query. It is recommended to be disabled.
    EOF
        description     = <<EOF
By default, performance statstics are disabled for all modules and not reported in the server log. Turning this parameter on causes logging of the performance of the relevant module and imposes a non-negligible performance penalty.
    EOF
        recommendations = <<EOF
Ensure the 'log_parser_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-statistics.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.10" {
      description = "GCP CIS 6.2.10 Ensure 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_planner_stats' != 'off'
            OR settings_database_flags ->> 'log_planner_stats' IS NULL);
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_planner_stats flag for a PostgreSQL instance controls the statistics monitoring for each query. It is recommended to be disabled.
    EOF
        description     = <<EOF
By default, performance statstics are disabled for all modules and not reported in the server log. Turning this parameter on causes logging of the performance of the relevant module and imposes a non-negligible performance penalty.
    EOF
        recommendations = <<EOF
Ensure the 'log_planner_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-statistics.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.11" {
      description = "GCP CIS 6.2.11 Ensure 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_executor_stats' != 'off'
            OR settings_database_flags ->> 'log_executor_stats' IS NULL);
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_executor_stats flag for a PostgreSQL instance controls the statistics monitoring for each query. It is recommended to be disabled.
    EOF
        description     = <<EOF
By default, performance statstics are disabled for all modules and not reported in the server log. Turning this parameter on causes logging of the performance of the relevant module and imposes a non-negligible performance penalty.
    EOF
        recommendations = <<EOF
Ensure the 'log_executor_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-statistics.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.12" {
      description = "GCP CIS 6.2.12 Ensure 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_statement_stats' != 'off'
            OR settings_database_flags ->> 'log_statement_stats' IS NULL);
    EOF
      risk {
        criticality     = "LOW"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_statement_stats flag for a PostgreSQL instance controls the statistics monitoring for each query. It is recommended to be disabled.
    EOF
        description     = <<EOF
By default, performance statstics are disabled for all modules and not reported in the server log. Turning this parameter on causes logging of the performance of the relevant module and imposes a non-negligible performance penalty.
    EOF
        recommendations = <<EOF
Ensure the 'log_statement_stats' database flag for Cloud SQL PostgreSQL instance is set to 'off'
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-statistics.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.13" {
      description   = "GCP CIS 6.2.13 Ensure that the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set appropriately (Manual)"
      expect_output = true
      query         = file("queries/manual.sql")
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_min_messages flag for a PostgreSQL instance controls the message level wrriten to the server log. It should be set appropriately according to the environment it is in.
    EOF
        description     = <<EOF
By default, `WARNING` level messages and above are reported and written to the server log. The changing of this parameter modifies which additional message types are reported and written to the server log. This should be set to the proper level according to the environment.    
    EOF
        recommendations = <<EOF
Ensure the 'log_min_messages' database flag for Cloud SQL PostgreSQL instance is set to the appropriate level.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-logging.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.14" {
      description = "GCP CIS 6.2.14 Ensure 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to 'Error' or stricter"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_min_error_statement' NOT IN('error', 'log', 'fatal', 'panic')
            OR settings_database_flags ->> 'log_min_error_statement' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_min_error_statement flag defines the minimum message severity level that is considered as an error statement. Messages for error statements are logged with the relevant SQL statement.
    EOF
        description     = <<EOF
ERROR is considered the best practice setting. Auditing helps in troubleshooting operational problems and also permits forensic analysis. If log_min_error_statement is not set to the correct value, messages may not be classified as error messages appropriately.
    EOF
        recommendations = <<EOF
Ensure the 'log_min_error_statement' database flag for Cloud SQL PostgreSQL instance is set to one of `ERROR`, `LOG`, `FATAL`, or `PANIC` as appropriate.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.0/runtime-config-logging.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.15" {
      description = "GCP CIS 6.2.15 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_temp_files' != '0'
            OR settings_database_flags ->> 'log_temp_files' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
PostgreSQL can create a temporary file for actions such as sorting, hashing and temporary query results when these operations exceed work_mem. The log_temp_files flag controls logging names and the file size when it is deleted.
    EOF
        description     = <<EOF
If all temporary files are not logged, it may be more difficult to identify potential performance issues that may be due to either poor application coding or deliberate resource starvation attempts.
    EOF
        recommendations = <<EOF
Ensure the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on).
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html
    EOF
        source          = "mage"
      }
    }

    query "6.2.16" {
      description = "GCP CIS 6.2.16 Ensure that the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled)"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'POSTGRES%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'log_min_duration_statement' != '-1'
            OR settings_database_flags ->> 'log_min_duration_statement' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The log_min_duration_statement flag defines the minimum amount of execution time of a statement in milliseconds where the total duration of the statement is logged.
    EOF
        description     = <<EOF
Logging SQL statements may include sensitive information that should not be recorded in logs. This recommendation is applicable to PostgreSQL database instances.
    EOF
        recommendations = <<EOF
Ensure the 'log_min_duration_statement' database flag for Cloud SQL PostgreSQL instance is set to '-1' (disabled).
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/flags#setting_a_database_flag
- https://www.postgresql.org/docs/9.6/runtime-config-logging.html
    EOF
        source          = "mage"
      }
    }

    query "6.3.1" {
      description = "GCP CIS 6.3.1 Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'external scripts enabled' != 'off'
            OR settings_database_flags ->> 'external scripts enabled' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set 'external scripts enabled' database flag for Cloud SQL SQL Server instance to off.
    EOF
        description     = <<EOF
The 'external scripts enabled' option is used to enable the execution of scripts with certain remote language extensions. This property is set to `OFF` by default and is recommended to remain disabled.
    EOF
        recommendations = <<EOF
Ensure the 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/external-scripts-enabled-server-configuration-option?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.3.2" {
      description = "GCP CIS 6.3.2 Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'cross db ownership chaining' != 'off'
            OR settings_database_flags ->> 'cross db ownership chaining' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance to off.
    EOF
        description     = <<EOF
The 'cross db ownership chaining' option is used to configure cross-database ownership chaining for an instance of Microsoft SQL Server. This server option allows you to control cross-database ownership chaining at the database level or to allow cross-database ownership chaining for all databases. Enabling cross db ownership is not recommended unless all of the databases hosted by the instance of SQL Server must participate in cross-database ownership chaining and you are aware of the security implications of this setting.
    EOF
        recommendations = <<EOF
Ensure the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off'.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.3.3" {
      description = "GCP CIS 6.3.3 Ensure 'user connections' database flag for Cloud SQL SQL Server instance is set as appropriate"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_database_flags IS NULL 
        OR settings_database_flags ->> 'user connections' IS NULL;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The 'user connections' option specifies the maximum number of simultaneous user connections that are allowed on an instance of SQL Server. The actual number of user connections allowed also depends on the version of SQL Server that you are using, and also the limits of your application or applications and hardware. SQL Server allows a maximum of 32,767 user connections.
    EOF
        description     = <<EOF
Because user connections is a dynamic (self-configuring) option, SQL Server adjusts the maximum number of user connections automatically as needed, up to the maximum value allowable. The default is 0, which means that the maximum (32,767) user connections are allowed. It is recommended that this option be reviewed and set appropriately.
    EOF
        recommendations = <<EOF
Ensure the 'user connections' database flag for Cloud SQL SQL Server instance is set appropriately.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-user-connections-server-configuration-option?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.3.4" {
      description = "GCP CIS 6.3.4 Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_database_flags IS NULL 
        OR settings_database_flags ->> 'user options' IS NOT NULL;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The 'user options' flag specifies global defaults for all users. A list of default query processing options is established for the duration of a user's work session. The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate).
    EOF
        description     = <<EOF
The user options option allows you to change the default values of the SET options (if the server's default settings are not appropriate). The default query processing options are considered sufficient and sane for nearly all configurations. It is recommended to leave 'user options' unconfigured.
    EOF
        recommendations = <<EOF
Ensure the 'user options' database flag for Cloud SQL SQL Server instance is not configured.
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-user-options-server-configuration-option?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.3.5" {
      description = "GCP CIS 6.3.5 Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'remote access' != 'off'
            OR settings_database_flags ->> 'remote access' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
The 'remote access' flag is an obscure SQL Server to SQL Server communication feature that is deprecated. It is recommended to be disabled.
    EOF
        description     = <<EOF
The remote access option controls the execution of stored procedures from local or remote servers on which instances of SQL Server are running. This default value for this option is 1. This grants permission to run local stored procedures from remote servers or remote stored procedures from the local server. To prevent local stored procedures from being run from a remote server or remote stored procedures from being run on the local server, set the option to 0.
    EOF
        recommendations = <<EOF
Ensure the 'remote access' database flag for Cloud SQL SQL Server instance is disabled (set to off).
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-remote-access-server-configuration-option?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.3.6" {
      description = "GCP CIS 6.3.6 Ensure '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> '3625' != 'off'
            OR settings_database_flags ->> '3625' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set '3625 (trace flag)' database flag for Cloud SQL SQL Server instance to off.
    EOF
        description     = <<EOF
Trace flags are frequently used to diagnose performance issues or to debug stored procedures or complex computer systems, but they may also be recommended by Microsoft Support to address behavior that is negatively impacting a specific workload.

All documented trace flags and those recommended by Microsoft Support are fully supported in a production environment when used as directed. 3625(trace log) Limits the amount of information returned to users who are not members of the sysadmin fixed server role, by masking the parameters of some error messages using '**'. This can help prevent disclosure of sensitive information, hence this is recommended to disable this flag.
    EOF
        recommendations = <<EOF
Ensure the '3625 (trace flag)' database flag for Cloud SQL SQL Server instance is disabled (set to off).
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/t-sql/database-console-commands/dbcc-traceon-trace-flags-transact-sql?view=sql-server-ver15
- https://hub.steampipe.io/mods/turbot/gcp_compliance/controls/control.cis_v120_6_3_6?context=benchmark.cis_v120/benchmark.cis_v120_6/benchmark.cis_v120_6_3
    EOF
        source          = "mage"
      }
    }

    query "6.3.7" {
      description = "GCP CIS 6.3.7 Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is set to 'off'"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND (settings_database_flags IS NULL 
            OR settings_database_flags ->> 'contained database authentication' != 'off'
            OR settings_database_flags ->> 'contained database authentication' IS NULL);
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to set the 'contained database authentication' database flag for Cloud SQL SQL Server instances to off.
    EOF
        description     = <<EOF
A contained database includes all database settings and metadata required to define the database and has no configuration dependencies on the instance of the Database Engine where the database is installed. Users can connect to the database without authenticating at the Database Engine level. Isolating the database from the Database Engine makes it possible to easily move the database to another instance of SQL Server.

Contained databases have some unique threats that should be understood and mitigated by SQL Server Database Engine administrators. Most of the threats are related to the USER WITH PASSWORD authentication process, which moves the authentication boundary from the Database Engine level to the database level, hence this is recommended to disable this flag.
    EOF
        recommendations = <<EOF
Ensure the 'contained database authentication' database flag for Cloud SQL SQL Server instances is disabled (set to off).
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/sqlserver/flags#setting_a_database_flag
- https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15
- https://docs.microsoft.com/en-us/sql/relational-databases/databases/security-best-practices-with-contained-databases?view=sql-server-ver15
    EOF
        source          = "mage"
      }
    }

    query "6.4" {
      description = "GCP CIS 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_ip_configuration_require_ssl = FALSE;
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to enforce all incoming connections to SQL database instance to use SSL.
    EOF
        description     = <<EOF
If a SQL database connection is successfully hijacked (such as in Man-in-the-Middle/MitM), sensitive data such as credentials, database queries, query outputs etc. may be disclosed. For security, it is recommended to always use SSL encryption when connecting to your instance.
    EOF
        recommendations = <<EOF
Ensure Cloud SQL database instances require all incoming connections to use SSL
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/postgres/configure-ssl-instance
    EOF
        source          = "mage"
      }
    }

    query "6.5" {
      description = "GCP CIS 6.5 Ensure that Cloud SQL database instances are not open to the world"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsisican.name, gsi.self_link as link
        FROM gcp_sql_instances gsi
        JOIN gcp_sql_instance_settings_ip_config_authorized_networks gsisican ON
        gsi.cq_id = gsisican.instance_cq_id
        WHERE database_version LIKE 'SQLSERVER%'
        AND gsisican.value = '0.0.0.0/0'
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that database servers should accept connections only from trusted Network(s)/IP(s) and restrict access from the world.
    EOF
        description     = <<EOF
To minimize attack surface on a Database server instance, only trusted/known and required IP(s) should be white-listed to connect to it.
    EOF
        recommendations = <<EOF
Ensure that Cloud SQL database instances are not open to the world
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/configure-ip
    EOF
        source          = "mage"
      }
    }

    query "6.6" {
      description = "GCP CIS 6.6 Ensure that Cloud SQL database instances do not have public IPs"
      query       = <<EOF
        SELECT gsi.project_id, gsi.name, gsiia."type", gsi.self_link as link
        FROM gcp_sql_instances gsi
        JOIN gcp_sql_instance_ip_addresses gsiia ON
        gsi.cq_id = gsiia.instance_cq_id
        WHERE database_version LIKE 'SQLSERVER%'
        AND gsiia.type = 'PRIMARY' OR backend_type != 'SECOND_GEN';
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to configure Cloud SQL database instances to use private IPs instead of public IPs.
    EOF
        description     = <<EOF
To lower an organization's attack surface, Cloud SQL databases should not have public IPs. Private IPs provide improved network security and lower latency for your application.
    EOF
        recommendations = <<EOF
Ensure that Cloud SQL database instances do not have public IPs
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/configure-private-ip
    EOF
        source          = "mage"
      }
    }

    query "6.7" {
      description = "GCP CIS 6.7 Ensure that Cloud SQL database instances are configured with automated backups"
      query       = <<EOF
        SELECT project_id, name, self_link as link
        FROM gcp_sql_instances gsi
        WHERE database_version LIKE 'SQLSERVER%'
        AND settings_backup_enabled = FALSE;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended to have all SQL database instances set to enable automated backups.
    EOF
        description     = <<EOF
Backups provide a way to restore a Cloud SQL instance to recover lost data or recover from a problem with that instance. Automated backups need to be set for any instance that contains data that should be protected from loss or damage.
    EOF
        recommendations = <<EOF
Ensure that Cloud SQL database instances are configured with automated backups
    EOF
        references      = <<EOF
- https://cloud.google.com/sql/docs/mysql/backup-recovery/backups
- https://cloud.google.com/sql/docs/postgres/backup-recovery/backing-up
    EOF
        source          = "mage"
      }
    }
  }

  policy "gcp-cis-section-7" {
    description = "GCP CIS Section 7"

    query "7.1" {
      description = "GCP CIS 7.1 Ensure that BigQuery datasets are not anonymously or publicly accessible"
      query       = <<EOF
        SELECT d.project_id, d.id, d.friendly_name, d.self_link AS dataset_link, a.special_group AS "group" , a."role"
        FROM gcp_bigquery_datasets d
        JOIN gcp_bigquery_dataset_accesses a ON
                d.id = a.dataset_id
        WHERE a."role" = 'allUsers'
        OR a."role" = 'allAuthenticatedUsers';
    EOF
      risk {
        criticality     = "HIGH"
        attack_surface  = "CLOUD"
        summary         = <<EOF
It is recommended that the IAM policy on BigQuery datasets does not allow anonymous and/or public access.
    EOF
        description     = <<EOF
Granting permissions to allUsers or allAuthenticatedUsers allows anyone to access the dataset. Such access might not be desirable if sensitive data is being stored in the dataset. Therefore, ensure that anonymous and/or public access to a dataset is not allowed.
    EOF
        recommendations = <<EOF
Ensure that BigQuery datasets are not anonymously or publicly accessible
    EOF
        references      = <<EOF
- https://cloud.google.com/storage/docs/access-control/iam-reference
- https://cloud.google.com/storage/docs/access-control/making-data-public
    EOF
        source          = "mage"
      }
    }

    query "7.2" {
      description = "GCP CIS 7.2 Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)"
      query       = <<EOF
        SELECT d.project_id, d.id, d.friendly_name, d.self_link as dataset_link, t.self_link as table_link
        FROM gcp_bigquery_datasets d
        JOIN gcp_bigquery_dataset_tables t ON
        d.id = t.dataset_id
        WHERE encryption_configuration_kms_key_name = '' OR  default_encryption_configuration_kms_key_name IS NULL;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. The data is encrypted using the data encryption keys and data encryption keys themselves are further encrypted using key encryption keys. This is seamless and do not require any additional input from the user.

However, if you want to have greater control, Customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets. If CMEK is used, the CMEK is used to encrypt the data encryption keys instead of using google-managed encryption keys.
    EOF
        description     = <<EOF
BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. This is seamless and does not require any additional input from the user.

Applying the Default Customer-managed keys on BigQuery data sets ensures that all the new tables created in the future will be encrypted using CMEK but existing tables need to be updated to use CMEK individually.
    EOF
        recommendations = <<EOF
Ensure that all BigQuery Tables are encrypted with Customer-managed encryption key (CMEK)
    EOF
        references      = <<EOF
- https://cloud.google.com/bigquery/docs/customer-managed-encryption
    EOF
        source          = "mage"
      }
    }

    query "7.3" {
      description = "GCP CIS 7.3 Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets"
      query       = <<EOF
        SELECT project_id, id, friendly_name, self_link as link
        FROM gcp_bigquery_datasets
        WHERE default_encryption_configuration_kms_key_name = '' 
        OR  default_encryption_configuration_kms_key_name IS NULL;
    EOF
      risk {
        criticality     = "MEDIUM"
        attack_surface  = "CLOUD"
        summary         = <<EOF
BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. The data is encrypted using the data encryption keys and data encryption keys themselves are further encrypted using key encryption keys. This is seamless and do not require any additional input from the user.

However, if you want to have greater control, Customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets. If CMEK is used, the CMEK is used to encrypt the data encryption keys instead of using google-managed encryption keys.
    EOF
        description     = <<EOF
BigQuery by default encrypts the data as rest by employing Envelope Encryption using Google managed cryptographic keys. This is seamless and does not require any additional input from the user.

For greater control over the encryption, customer-managed encryption keys (CMEK) can be used as encryption key management solution for BigQuery Data Sets. Setting a Default Customer-managed encryption key (CMEK) for a data set ensure any tables created in future will use the specified CMEK if none other is provided.
    EOF
        recommendations = <<EOF
Ensure that a Default Customer-managed encryption key (CMEK) is specified for all BigQuery Data Sets
    EOF
        references      = <<EOF
- https://cloud.google.com/bigquery/docs/customer-managed-encryption
    EOF
        source          = "mage"
      }
    }
  }
}
