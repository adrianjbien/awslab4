var moment = require("moment");
var crypto = require("crypto");

// AWS Signature Version 4 - stałe
var ALGORITHM = "AWS4-HMAC-SHA256";
var SERVICE = "s3";
var REQUEST_TYPE = "aws4_request";

// Nazwy pól formularza
var CREDENTIAL_FIELD_NAME = "x-amz-credential";
var ALGORITHM_FIELD_NAME = "x-amz-algorithm";
var DATE_FIELD_NAME = "x-amz-date";
var POLICY_FIELD_NAME = "policy";
var SIGNATURE_FIELD_NAME = "x-amz-signature";

/**
 * Klasa Policy - zarządza dokumentem polityki S3
 * @param {Object} policyData - dane polityki z policy.json
 * @param {Object} awsConfig - konfiguracja AWS (region, accessKeyId)
 */
var Policy = function(policyData, awsConfig) {
	this.policy = JSON.parse(JSON.stringify(policyData)); // deep copy
	this.awsConfig = awsConfig;

	// Oblicz datę wygaśnięcia (np. +1 dzień)
	this.policy.expiration = moment().add(policyData.expiration).toISOString();

	// Data w formacie YYYYMMDD'T'HHMMSS'Z' (wymagane przez AWS V4)
	this.amzDate = moment().utc().format("YYYYMMDD[T]HHmmss[Z]");
	// Data w formacie YYYYMMDD (do credential scope)
	this.dateStamp = moment().utc().format("YYYYMMDD");

	// Credential string: ACCESS_KEY/DATE/REGION/s3/aws4_request
	this.credential = awsConfig.accessKeyId + "/" +
		this.dateStamp + "/" +
		awsConfig.region + "/" +
		SERVICE + "/" +
		REQUEST_TYPE;

	// Dodaj wymagane warunki V4 do polityki
	this.policy.conditions.push({"x-amz-credential": this.credential});
	this.policy.conditions.push({"x-amz-algorithm": ALGORITHM});
	this.policy.conditions.push({"x-amz-date": this.amzDate});

	console.log("Policy created with expiration: " + this.policy.expiration);
	console.log("Credential: " + this.credential);
};

/**
 * Koduje politykę do base64
 */
Policy.prototype.generateEncodedPolicyDocument = function() {
	var stringPolicy = JSON.stringify(this.policy);
	return Buffer.from(stringPolicy).toString('base64');
};

/**
 * Generuje Signing Key dla AWS Signature V4
 * SigningKey = HMAC-SHA256(HMAC-SHA256(HMAC-SHA256(HMAC-SHA256("AWS4"+secret, date), region), service), "aws4_request")
 */
Policy.prototype.getSigningKey = function(secretAccessKey) {
	var kDate = crypto.createHmac('sha256', "AWS4" + secretAccessKey)
		.update(this.dateStamp).digest();
	var kRegion = crypto.createHmac('sha256', kDate)
		.update(this.awsConfig.region).digest();
	var kService = crypto.createHmac('sha256', kRegion)
		.update(SERVICE).digest();
	var kSigning = crypto.createHmac('sha256', kService)
		.update(REQUEST_TYPE).digest();
	return kSigning;
};

/**
 * Generuje podpis V4 dla zakodowanej polityki
 */
Policy.prototype.generateSignature = function(secretAccessKey) {
	var encodedPolicy = this.generateEncodedPolicyDocument();
	var signingKey = this.getSigningKey(secretAccessKey);
	var signature = crypto.createHmac('sha256', signingKey)
		.update(encodedPolicy).digest('hex');
	return signature;
};

/**
 * Pobiera wartość warunku z polityki po kluczu
 */
Policy.prototype.getConditionValueByKey = function(key) {
	var condition = null;
	this.policy.conditions.forEach(function(elem) {
		if (typeof elem === 'object' && !Array.isArray(elem)) {
			if (Object.keys(elem)[0] === key) {
				condition = elem[key];
			}
		}
	});
	return condition;
};

/**
 * Pobiera warunki polityki
 */
Policy.prototype.getConditions = function() {
	return this.policy.conditions;
};

/**
 * Gettery dla danych V4
 */
Policy.prototype.getCredential = function() {
	return this.credential;
};

Policy.prototype.getAmzDate = function() {
	return this.amzDate;
};

/**
 * Klasa S3Form - generuje pola formularza HTML
 * @param {Policy} policy - obiekt Policy
 */
var S3Form = function(policy) {
	if (!(policy instanceof Policy)) {
		throw new Error("policy must be instance of Policy");
	}
	this.policy = policy;
};

/**
 * Generuje ukryte pola formularza z warunków polityki
 * Pomija: bucket, x-amz-credential, x-amz-algorithm, x-amz-date (dodawane osobno)
 */
S3Form.prototype.generateS3FormFields = function() {
	var conditions = this.policy.getConditions();
	var formFields = [];

	// Pola do pominięcia (dodajemy je w addS3CredentialsFields)
	var skipFields = ["bucket", "x-amz-credential", "x-amz-algorithm", "x-amz-date"];

	conditions.forEach(function(elem) {
		if (Array.isArray(elem)) {
			// Warunek typu ["starts-with", "$key", "prefix/"]
			if (elem[0] === "starts-with" && elem[1] === "$key") {
				formFields.push(hiddenField("key", elem[2] + "${filename}"));
			}
			// Warunki starts-with dla metadanych pomijamy - dodamy je osobno
		} else if (typeof elem === 'object') {
			// Warunek typu {"acl": "private"}
			var key = Object.keys(elem)[0];
			var value = elem[key];
			if (skipFields.indexOf(key) === -1) {
				formFields.push(hiddenField(key, value));
			}
		}
	});

	return formFields;
};

/**
 * Dodaje pola uwierzytelniające AWS Signature V4
 */
S3Form.prototype.addS3CredentialsFields = function(fields, awsConfig) {
	// x-amz-credential
	fields.push(hiddenField(CREDENTIAL_FIELD_NAME, this.policy.getCredential()));

	// x-amz-algorithm
	fields.push(hiddenField(ALGORITHM_FIELD_NAME, ALGORITHM));

	// x-amz-date
	fields.push(hiddenField(DATE_FIELD_NAME, this.policy.getAmzDate()));

	// policy (base64)
	fields.push(hiddenField(POLICY_FIELD_NAME, this.policy.generateEncodedPolicyDocument()));

	// x-amz-signature
	fields.push(hiddenField(SIGNATURE_FIELD_NAME, this.policy.generateSignature(awsConfig.secretAccessKey)));

	return fields;
};

// Zachowanie starej nazwy dla kompatybilności wstecznej
S3Form.prototype.addS3CredientalsFields = S3Form.prototype.addS3CredentialsFields;

/**
 * Tworzy obiekt ukrytego pola formularza
 */
function hiddenField(fieldName, value) {
	return { name: fieldName, value: value };
}

exports.Policy = Policy;
exports.S3Form = S3Form;
