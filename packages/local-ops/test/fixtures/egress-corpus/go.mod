module github.com/acme/settlement

go 1.24

require (
	github.com/aws/aws-sdk-go-v2/service/s3 v1.66.0
	github.com/google/uuid v1.6.0
)

exclude github.com/aws/aws-sdk-go v1.44.0 // planted negative: an exclude names no dependency, so this must not add a second s3.amazonaws.com call site
