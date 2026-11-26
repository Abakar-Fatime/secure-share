# Deploying secure-share to AWS

After a one-time setup, every push to `main` deploys automatically. No AWS access keys are created or stored: GitHub Actions proves its identity to AWS with OpenID Connect and receives short-lived credentials for one role that only this repository's `main` branch can use.

Everything below is done in the browser.

## 1. AWS account

1. Create an account at https://aws.amazon.com/free and choose the **Free plan**. New accounts get free credits, which comfortably cover this app.
2. In the AWS console, pick the region in the top-right corner. The default for this project is **Asia Pacific (Tokyo) ap-northeast-1**. If you choose another region, also set the `AWS_REGION` variable in step 3.

## 2. One-time AWS setup (CloudFormation)

1. Download [`infra/bootstrap/github-deploy.yaml`](../infra/bootstrap/github-deploy.yaml) from this repository.
2. In the AWS console open **CloudFormation → Create stack → With new resources**.
3. Choose **Upload a template file**, select the downloaded file, then **Next**.
4. Stack name: `secure-share-bootstrap`. Keep `GitHubRepo` as your `owner/repository`. **Next**, **Next**.
5. Tick "I acknowledge that AWS CloudFormation might create IAM resources with custom names" and **Submit**.
6. When the status is `CREATE_COMPLETE`, open the **Outputs** tab and keep `DeployRoleArn` and `StateBucketName`.

This creates the GitHub identity provider, the deploy role, and a private, versioned bucket for Terraform state.

## 3. Connect GitHub

In the GitHub repository: **Settings → Secrets and variables → Actions → Variables → New repository variable**.

| Name | Value |
|---|---|
| `AWS_DEPLOY_ROLE_ARN` | `DeployRoleArn` from step 2 |
| `TF_STATE_BUCKET` | `StateBucketName` from step 2 |
| `AWS_REGION` | only if not `ap-northeast-1` |
| `BUDGET_EMAIL` | optional: AWS emails you if the monthly cost forecast passes $5 |

## 4. Deploy

**Actions → Deploy to AWS → Run workflow.** The first run takes about 5–10 minutes (CloudFront is the slow part). The run summary shows the app's address, for example `https://d1234abcd.cloudfront.net`.

## 5. Create the first admin

1. In the AWS console, click the **CloudShell** icon (top bar) to open a terminal in your account.
2. Paste, with your own email and name:

   ```bash
   aws lambda invoke --function-name secure-share-api \
     --cli-binary-format raw-in-base64-out \
     --payload '{"ss_cli":"create-admin","email":"you@example.com","name":"Your Name"}' \
     out.json && cat out.json
   ```

3. Open the `invite_url` it prints, choose a password, then go to **Account → Two-step verification → Turn on**. Admin pages open once two-step verification is on.
4. Invite everyone else from **People**.

## 6. Optional: Sign in with Google

1. In the Google Cloud console, create an **OAuth client ID** of type *Web application*.
2. Authorised redirect URI: `https://<your-app-address>/api/auth/google/callback`.
3. In GitHub add the variable `GOOGLE_CLIENT_ID` and the **secret** `GOOGLE_CLIENT_SECRET`, then run the deploy workflow again.

People can then use Google to sign in to accounts an admin has already created with the same email.

## Removing everything

Run **Actions → Destroy AWS resources**, type `destroy` to confirm. Then delete the `secure-share-bootstrap` stack in CloudFormation (empty the state bucket first if AWS asks).
