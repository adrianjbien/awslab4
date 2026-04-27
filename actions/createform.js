var os = require("os");
var helpers = require("../helpers");
var Policy = require("../s3post").Policy;
var S3Form = require("../s3post").S3Form;

var AWS_CONFIG_FILE = "config.json";
var POLICY_FILE = "policy.json";
var INDEX_TEMPLATE = "index.ejs";

var task = function(request, callback){
	// 1. Wczytaj konfigurację AWS i politykę z plików JSON
	var awsConfig = helpers.readJSONFile(AWS_CONFIG_FILE);
	var policyData = helpers.readJSONFile(POLICY_FILE);

	// 2. Utwórz obiekt Policy - wymaga awsConfig dla AWS Signature V4
	//    (oblicza datę wygaśnięcia, credential string, koduje do base64)
	var policy = new Policy(policyData, awsConfig);

	// 3. Utwórz obiekt S3Form - generuje pola formularza na podstawie polityki
	var s3Form = new S3Form(policy);

	// 4. Wygeneruj ukryte pola formularza z warunków polityki
	//    (key, acl, success_action_redirect)
	var fields = s3Form.generateS3FormFields();

	// 5. Dodaj pola uwierzytelniające AWS (AWSAccessKeyId, policy, signature)
	s3Form.addS3CredientalsFields(fields, awsConfig);

	// 6. Dodaj metadane (imię i nazwisko + adres IP serwera)
	//    Te pola zostaną zapisane jako metadane obiektu w S3
	fields.push({name: "x-amz-meta-name", value: "Adrian Krombal"});
	fields.push({name: "x-amz-meta-ip", value: getServerAddress()});

	// 7. Pobierz nazwę kubełka z polityki
	var bucket = policy.getConditionValueByKey("bucket");

	// 8. Zbuduj URL do wysyłki formularza (endpoint S3)
	var url = "https://" + bucket + ".s3." + awsConfig.region + ".amazonaws.com/";

	// 9. Zwróć szablon index.ejs z danymi (fields, bucket, url)
	callback(null, {
		template: INDEX_TEMPLATE,
		params: {
			fields: fields,
			bucket: bucket,
			url: url
		}
	});

// 	po tym wyliczamy skroty dla pliku ktory pobieramy i tez wyswietlamy metadane

};

// Funkcja pomocnicza - pobiera adres IP serwera
function getServerAddress() {
	var interfaces = os.networkInterfaces();
	for (var name in interfaces) {
		var iface = interfaces[name];
		for (var i = 0; i < iface.length; i++) {
			var alias = iface[i];
			// Szukamy adresu IPv4, który nie jest localhost
			if (alias.family === 'IPv4' && !alias.internal) {
				return alias.address;
			}
		}
	}
	// Fallback - zwróć hostname jeśli nie znaleziono IP
	return os.hostname();
}

exports.action = task;
