var os = require("os");
var helpers = require("../helpers");
var AWS = require("aws-sdk");

AWS.config.loadFromPath('./config.json');
var s3 = new AWS.S3();

var task = function(request, callback){

	// 🔥 dane z redirectu S3
	var key = request.query.key;
	var bucket = request.query.bucket;

	if (!key || !bucket) {
		return callback(null, "Brak key lub bucket w request");
	}

	var params = {
		Bucket: bucket,
		Key: key
	};

	s3.getObject(params, function(err, data) {
		if (err) {
			return callback(null, "Błąd pobierania: " + err);
		}

		var content = data.Body.toString();

		var metadata = data.Metadata;

		helpers.calculateMultiDigest(
			content,
			["md5", "sha1", "sha256"],
			function(err, digests) {

				var result = "";

				result += "<h3>Plik: " + key + "</h3>";

				result += "<h4>Metadata:</h4>";
				for (var m in metadata) {
					result += m + ": " + metadata[m] + "<br>";
				}

				result += "<h4>Skróty:</h4>";
				result += digests.join("<br>");

				result += "<hr>Service: " + os.hostname();

				callback(null, result);
			},
			1
		);
	});
};

exports.action = task;