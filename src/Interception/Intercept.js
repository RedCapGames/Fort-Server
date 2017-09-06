//var methods = [];
var Backtory = require("backtory-sdk");
var _ = require("./../lodash/lodash");
var UUID = require("./../uuid/uuid.js");
var matchTokens=[39, 118, 0, 86, 77, 226, 202, 65, 128, 8, 232, 62, 229, 16, 22, 125];

function CheckUserAndAdd(requestBody, context, finalAction) {
    var userId = context.getSecurityContext().userId;
    var securityContex = context.getSecurityContext();
    var userName = context.getSecurityContext().userName;
    var UserData = Backtory.Object.extend("Userdata");
    var query = new Backtory.Query(UserData);
    query.equalTo("UserId", userId);
    query.find({
        success: function (results) {
            if (results.length > 0){
                if(results[0].get("IsActive") === false) {
                    context.fail("User Inactive")
                }
                else{
                    finalAction(results[0]);
                }
            }
            else {
                var Settings = Backtory.Object.extend("Settings");
                var query = new Backtory.Query(Settings);
                query.equalTo("Tag","Fort");
                query.find({
                    success: function (results) {
                        var userData = new UserData();
                        var result = results[0];
                        if(result != undefined){
                            var settings = result.get("Settings");
                            var values={};
                            for(var i=0;i<settings.ValuesDefenition.length;i++){
                                values[settings.ValuesDefenition[i]] = settings.StartupValues[settings.ValuesDefenition[i]];
                            }
                            userData.set("Values", values);
                        }
                        userData.set("Score", 0);
                        userData.set("LastAddId", 0);
                        userData.set("UserId", userId);
                        userData.set("UserName", userName);
                        userData.save({
                            success: function (savedUserData) {
                                // Execute any logic that should take place after the object is saved.						
                                finalAction(savedUserData);
                            },
                            error: function (error) {
                                // Execute any logic that should take place if the save fails.
                                finalAction(null);
                            }
                        });
                    },
                    error: function (object, error) {
                        finalAction(null);
                    }
                });

            }
        },
        error: function (error) {
            finalAction(null);
        }
    });
}
var deleteItems = function (index, userTokens, success, failed) {
    if(index>=userTokens.length){
        success();
    }
    else{
        userTokens[index].destroy({
            success: function(results) {
                deleteItems(index+1,userTokens,success,failed);
            },
            error: function(error) {
                deleteItems(index+1,userTokens,success,failed);
            }
        });
    }
}
var clearExpiredTokens = function (now,success, failed) {
    var MethodTokens = Backtory.Object.extend("MethodTokens");
    var expiredQuery = new Backtory.Query(MethodTokens);
    expiredQuery.lessThan("ExpireDate", now+0);

    var usedQuery = new Backtory.Query(MethodTokens);
    usedQuery.equalTo("Used", true);

    var query = Backtory.Query.or(expiredQuery, usedQuery);
    query.find({
        success: function(results) {
            deleteItems(0,results,success,failed);
        },
        error: function(error) {
            failed();
        }
    });
}
exports.Intercept = function (func) {
    var interceptionFunction = function (requestBody, context) {
        if (context.getSecurityContext().keyType !== null) {
            if(_.has(func,"MasterOnly") && func.MasterOnly && context.getSecurityContext().keyType !=="master") {
                context.fail("Master Only");
            }else {
                if(_.has(func,"CheckToken")&&func.CheckToken){
                    if(!_.has(requestBody,"tokens") || !_.isArray(requestBody.tokens) || requestBody.tokens.length != 16) {
                        context.fail("Invalid Parameter");
                        return;
                    }
                    var MethodTokens = Backtory.Object.extend("MethodTokens");
                    var query = new Backtory.Query(MethodTokens);
                    var tokensBinary = _.clone(requestBody.tokens);
                    for(var i=0;i<16;i++){
                        tokensBinary[i] = tokensBinary[i]^matchTokens[i];
                    }
                    var c = tokensBinary[0];
                    tokensBinary[0] = tokensBinary[3];
                    tokensBinary[3] = c;
                    c = tokensBinary[1];
                    tokensBinary[1] = tokensBinary[2];
                    tokensBinary[2] = c;
                    c = tokensBinary[4];
                    tokensBinary[4] = tokensBinary[5];
                    tokensBinary[5] = c;

                    c = tokensBinary[6];
                    tokensBinary[6] = tokensBinary[7];
                    tokensBinary[7] = c;

                    var token = UUID.fromBytes(tokensBinary).toString();
                    query.equalTo("Token",token);
                    clearExpiredTokens(Date.now(),function () {
                        query.find({
                            success: function (results) {
                                if(results.length==0){
                                    context.fail("Token not found");
                                    return;
                                }
                                if(results[0].get("Used")){
                                    context.fail("Token already used");
                                    return;
                                }
                                var expireDate = results[0].get("ExpireDate");

                                if(expireDate<Date.now()+0) {
                                    context.fail("Token Expired");
                                    return;
                                }
                                results[0].set("Used",true);
                                results[0].save({
                                    success: function (savedUserData) {
                                        CheckUserAndAdd(requestBody.data, context, function(userData) {
                                            if (userData == null) {
                                                context.fail();
                                            } else {
                                                context.userData = userData;
                                                func(requestBody, context);
                                            }
                                        });
                                    },
                                    error: function (error) {
                                        // Execute any logic that should take place if the save fails.
                                        context.fail("Internal server error");
                                    }
                                });
                            },
                            error: function (object, error) {
                                context.fail("Token not found");
                            }
                        });
                    },function () {
                        context.fail("Internal Server Error");
                    });

                }
                else{
                    CheckUserAndAdd(requestBody, context, function(userData) {
                        if (userData == null) {
                            context.fail();
                        } else {
                            context.userData = userData;
                            func(requestBody, context);
                        }
                    });
                }
            }
        } else {
            func(requestBody, context);
        }
        
    }
    return interceptionFunction;
}