var AWS = require("aws-sdk");
const helpers = require("../helpers");

AWS.config.loadFromPath('./config.json');
var POLICY_FILE = "policy.json";

var s3 = new AWS.S3();

var task = function(request, callback){

    var policyData = helpers.readJSONFile(POLICY_FILE);

    const bucket = policyData.conditions[1].bucket;

    var params = {
        Bucket: bucket,
        Key: "adrian/victoria.txt"
    };


    s3.getObject(params, function(err, data) {
        if (err) console.log(err, err.stack); // an error occurred
        else     console.log(data);           // successful response

    });
}

exports.action = task;