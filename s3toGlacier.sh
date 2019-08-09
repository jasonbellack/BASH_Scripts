#!/bin/bash
   
   #Create the S3 bucket and choose it's region
echo "Please select a name for the bucket: "
read BUCKETNAME
echo "Which AWS Region do you want the bucket in? "
read REGION
while ! [[ $REGION =~ ^(us-east-1|us-east-2|us-west-1|us-west-2|ap-south-1|ap_northeast-3|ap-northeast-2|ap-southeast-1|\
     ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|\
     eu-west-3|eu-north-1|sa-east-1|us-gov-east-1|us-gov-west-1)$ ]]; do
     echo "You did not choose an active AWS region. Please select an active region for the bucket. ";
     read REGION;
     done
if [ $REGION = us-east-1 ];then
BUCKETURL=$(aws s3api create-bucket --bucket $BUCKETNAME --region $REGION --output text);
echo "The file path for the new bucket is: " $BUCKETURL;
elif [[ $REGION =~ ^(us-east-2|us-west-1|us-west-2|ap-south-1|ap_northeast-3|ap-northeast-2|ap-southeast-1|\
     ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|\
     eu-west-3|eu-north-1|sa-east-1|us-gov-east-1|us-gov-west-1)$ ]]; then
     BUCKETURL=$(aws s3api create-bucket --bucket $BUCKETNAME --region $REGION --create-bucket-configuration LocationConstraint=$REGION --output text);
     echo "The file path for the new bucket is: " $BUCKETURL;
fi
​
   #Set up the backup for the bucket in a different region from where the original was created.
echo "Choose a region for the bucket's backup: "
read REGION2
while ! [[ $REGION2 =~ ^(us-east-1|us-east-2|us-west-1|us-west-2|ap-south-1|ap_northeast-3|ap-northeast-2|ap-southeast-1|\
     ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|\
     eu-west-3|eu-north-1|sa-east-1|us-gov-east-1|us-gov-west-1)$ ]]; do
     echo "You did not choose an active AWS region. Please select an active region for the backup bucket. ";
     read REGION2;
  while [ $REGION2 = $REGION ];do
       echo "Backup bucket cannot be in the same region. Please select a different region";
       read REGION2;
      done;
     done
while [ $REGION2 = $REGION ];do
       echo "Backup bucket cannot be in the same region. Please select a different region";
       read REGION2;
      done
  if [ $REGION2 = us-east-1 ];then
   BUCKETURLBKUP=$(aws s3api create-bucket --bucket $BUCKETNAME-backup --region $REGION2 --output text);
  elif [[ $REGION2 =~ ^(us-east-2|us-west-1|us-west-2|ap-south-1|ap_northeast-3|ap-northeast-2|ap-southeast-1|\
       ap-southeast-2|ap-northeast-1|ca-central-1|cn-north-1|cn-northwest-1|eu-central-1|eu-west-1|eu-west-2|\
       eu-west-3|eu-north-1|sa-east-1|us-gov-east-1|us-gov-west-1)$ ]];then
   BUCKETURLBKUP=$(aws s3api create-bucket --bucket $BUCKETNAME-backup --region $REGION2 --create-bucket-configuration LocationConstraint=$REGION2 --output text);
  fi
echo "The filepath for the backup bucket is: " $BUCKETURLBKUP
   
   #Enable versioning on both buckets
aws s3api put-bucket-versioning --bucket $BUCKETNAME --versioning-configuration Status=Enabled
aws s3api put-bucket-versioning --bucket $BUCKETNAME-backup --versioning-configuration Status=Enabled
​
   # Create an IAM role with a trust policy that allows Amazon S3 principal permissions. 
   # If an IAM role has already been created, it will need to be used instead of the IAMROLE
   # created by the script.
echo '{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Principal":{
            "Service":"s3.amazonaws.com"
         },
         "Action":"sts:AssumeRole"
      }
   ]
}' > S3-role-trust-policy.json
echo "Please select a name for the IAM Role that will allow replication of objects: "
read IAMROLE
aws iam create-role --role-name $IAMROLE --assume-role-policy-document file://S3-role-trust-policy.json > role.json
​
   #Attach permissions policy to the newly created role
echo '{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Action":[
            "s3:GetObjectVersionForReplication",
            "s3:GetObjectVersionAcl"
         ],
         "Resource":[
            "arn:aws:s3:::'$BUCKETNAME'/*"
         ]
      },
      {
         "Effect":"Allow",
         "Action":[
            "s3:ListBucket",
            "s3:GetReplicationConfiguration"
         ],
         "Resource":[
            "arn:aws:s3:::'$BUCKETNAME'"
         ]
      },
      {
         "Effect":"Allow",
         "Action":[
            "s3:ReplicateObject",
            "s3:ReplicateDelete",
            "s3:ReplicateTags",
            "s3:GetObjectVersionTagging"
​
         ],
         "Resource":"arn:aws:s3:::'$BUCKETNAME'-backup/*"
      }
   ]
}' > S3-role-permissions-policy.json
​
   # If a policy is already in place for cross region replication, that policy
   # will need to be entered below in place of the S3POLICY variable. 
echo "Please select a name for the policy that will allow replication of objects: "
read S3POLICY
aws iam put-role-policy --role-name $IAMROLE --policy-document file://S3-role-permissions-policy.json --policy-name $S3POLICY > /dev/null
​
   #Configure replication to the source bucket
ACCOUNT=$(aws sts get-caller-identity --output text --query 'Account')
echo '{
   "Role": "arn:aws:iam::'$ACCOUNT':role/'$IAMROLE'",
   "Rules": [
     {
       "Status": "Enabled",
       "Priority": 1,
       "DeleteMarkerReplication": { "Status": "Disabled" },
       "Filter" : { "Prefix": ""},
       "Destination": {
         "Bucket": "arn:aws:s3:::'$BUCKETNAME'-backup",
         "StorageClass": "GLACIER"
       }
     }
   ]
 }' > replication.json
aws s3api put-bucket-replication --bucket $BUCKETNAME --replication-configuration  file://replication.json
rm replication.json 
rm S3-role-trust-policy.json 
rm S3-role-permissions-policy.json
