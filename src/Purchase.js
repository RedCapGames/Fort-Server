﻿var interception = require("./Interception/Intercept.js");
var Backtory = require("backtory-sdk");
var _ = require("./lodash/lodash");
var iapProvider = require("./IapProviders/IapProvider");
var BacktoryHelper = require("./Helpers/backtoryHelper");
exports.GetSupportedIapMarkets = interception.Intercept(function (requestBody, context) {
    context.succeed(iapProvider.getProvidersName());
});
var GetPackageResponseFromPackage = function(object)
{
    return {PackageData:object.get("PackageData")||null,Price:object.get("Price"),Sku:object.get("Sku"),Values:object.get("Values")||{},Markets:markets,PackageType:object.get("PackageType")};
};
exports.GetIapPackages = interception.Intercept(function (requestBody, context) {
    var packageType = _.has(requestBody,"packageType")?requestBody.packageType:0;
    var Packages = Backtory.Object.extend("Packages");
    var query = new Backtory.Query(Packages);
    query.equalTo("PackageType",packageType);
    query.find({
        success: function(results) {
            var result = [];
            for (var i = 0; i < results.length; i++) {
                var object = results[i];
                var markets = object.get("Markets");
                if(markets == null || markets.length ==0){
                    markets = iapProvider.getProvidersName();
                }
                result.push(GetPackageResponseFromPackage(object));
            }
            context.succeed(result);
        },
        error: function(error) {
            context.fail("Internal server error");
        }
    });
});

exports.GetPurchasedIap = interception.Intercept(function (requestBody, context) {
    var UserPackagePurchase = Backtory.Object.extend("UserPackagePurchase");
    var query = new Backtory.Query(UserPackagePurchase);
    query.equalTo("User",context.userData);
    query.find({
        success: function(results) {

            var packages = _.map(results,function (userPackagePurchase) {
                return userPackagePurchase.get("Package");
            });
            BacktoryHelper.fetchAll(packages,{success:function (packages) {
                var result = [];
                for (var i = 0; i < results.length; i++) {
                    var object = results[i];
                    result.push({Sku:packages[i].get("Sku"),Price:object.get("Price"),Market:object.get("Market"),	PurchaseToken:object.get("PurchaseToken"),DisplayName:object.get("DisplayName")});
                }
                context.succeed(result);
            },error:function () {
                context.fail("Internal server error");
            }});

        },
        error: function(error) {
            context.fail("Internal server error");
        }
    });
});

var resolveMarketConfig = function (marketName,context,resultAction) {
    var Markets = Backtory.Object.extend("Markets");
    var query = new Backtory.Query(Markets);
    query.equalTo("Name",marketName);
    query.find({success:function (markets) {
        if(markets.length!=1){
            context.fail("Market settings cannot be resolved");
        }
        else{
            resultAction(markets[0].get("Config"));
        }

    },error:function (error) {
        context.fail("Market settings cannot be resolved");
    }})
};

exports.PurchaseIapPackage = interception.Intercept(function (requestBody, context) {
    if(!_.has(requestBody,"market")|| !_.isString(requestBody.market)){
        context.fail("market parameter is needed");
        return;
    }
    if(!_.has(requestBody,"payload")|| !_.isString(requestBody.payload)){
        context.fail("payload parameter is needed");
        return;
    }

    if(!_.has(requestBody,"sku")|| !_.isString(requestBody.sku)){
        context.fail("sku parameter is needed");
        return;
    }

    if(!_.has(requestBody,"purchaseToken")|| !_.isString(requestBody.purchaseToken)){
        context.fail("purchaseToken parameter is needed");
        return;
    }
    var provider = iapProvider.getProvider(requestBody.market);
    if(provider == null)
    {
        context.fail("Iab Market is not defined");
        return;
    }
    resolveMarketConfig(requestBody.market,context,function (marketConfig) {
        provider.checkPurchase(requestBody.payload,requestBody.purchaseToken,requestBody.sku,marketConfig,function (succeed) {
            if(!succeed){
                context.succeed({MarketSuccess:false});
            } else{
                var Packages = Backtory.Object.extend("Packages");
                var query = new Backtory.Query(Packages);
                query.equalTo("Sku",requestBody.sku);
                query.find({
                    success: function (results) {
                        if(results.length==0){
                            context.fail("Sku not found");
                        }else{
                            var package = results[0];
                            var UserPackagePurchase = Backtory.Object.extend("UserPackagePurchase");
                            var query = new Backtory.Query(UserPackagePurchase);
                            //query.equalTo("Package",package);
                            query.equalTo("PurchaseToken",requestBody.purchaseToken);
                            query.count({
                                success: function (count) {
                                    if(count > 0){
                                        context.fail("Purchase Token already Used");
                                    }else{
                                        var userPackagePurchase = new UserPackagePurchase();
                                        userPackagePurchase.set("Package",package);
                                        userPackagePurchase.set("Market",requestBody.market);
                                        userPackagePurchase.set("Price",package.get("Price"));
                                        userPackagePurchase.set("PurchaseToken",requestBody.purchaseToken);
                                        userPackagePurchase.set("User",userData);
                                        userPackagePurchase.save({success:function (userPackagePurchase) {
                                            context.succeed({MarketSuccess:true});
                                        },error:function (error) {
                                            context.fail("Internal server Error");
                                        }});
                                    }
                                },
                                error: function (error) {
                                    context.fail("InternalServerError");
                                }
                            });
                        }
                    },
                    error: function (error) {
                        context.fail("InternalServerError");
                    }
                });

                /*           var UserPackagePurchase = Backtory.Object.extend("UserPackagePurchase");
                 var query = new Backtory.Query(UserPackagePurchase);
                 query.equalTo("")
                 query.count({
                 success: function (count) {
                 },
                 error: function (error) {
                 context.fail("InternalServerError");
                 }
                 });*/
            }
        });
    });

});

exports.GetItems = interception.Intercept(function (requestBody, context) {
    var Items = Backtory.Object.extend("Items");
    var query = new Backtory.Query(Items);
    query.find({
        success: function(results) {
            var result = [];
            for (var i = 0; i < results.length; i++) {
                var object = results[i];
                if(_.has(requestBody,"Full")) {
                    result.push({ItemId:object.get("ItemId"),RentCost:object.get("RentCost"),PurchaseCost:object.get("PurchaseCost"),Name:object.get("Name")});
                }
                else{
                    result.push({ItemId:object.get("ItemId"),RentCost:object.get("RentCost"),PurchaseCost:object.get("PurchaseCost")});
                }

            }
            context.succeed(result);
        },
        error: function(error) {
            context.fail("Internal server error");
        }
    });
});

exports.GetPurchasedItems = interception.Intercept(function (requestBody, context) {
    var relation = context.userData.relation("PurchasedItems");
    BacktoryHelper.fetchAll(BacktoryHelper.getRelationObjects(relation),{success:function (results) {

        context.succeed(_.map(_.filter(results,function (result) {
            return result !== null;
        }),function (result) {
            return result.get("ItemId");
        }));
    },error:function () {
        context.fail("Internal server error");
    }});
});
var UpdateOrAddPurchaseItem = function (items, index, actionResult) {
    if(index===items.length){
        actionResult(true);
        return;
    }
    var Items = Backtory.Object.extend("Items");
    var query = new Backtory.Query(Items);
    query.equalTo("ItemId",items[index].ItemId);
    query.find({
        success: function(results) {
            var item;
            if(results.length===0){
                item = new Items();
                item.set("ItemId",items[index].ItemId);

            }else{
                item = results[0];
            }
            item.set("Name",items[index].Name);
            item.set("RentCost",items[index].RentCost);
            item.set("PurchaseCost",items[index].PurchaseCost);
            item.save({
                success: function (savedUserData) {
                    UpdateOrAddPurchaseItem(items,index+1,actionResult);
                },
                error: function (error) {
                    actionResult(false);
                }
            });
        },
        error: function(error) {
            actionResult(false);
        }
    });
};
var UpdateItems = function (requestBody, context) {
    if(!_.has(requestBody,"Items") || !_.isArray(requestBody.Items))
    {
        context.fail("Invalid Parameter");
        return;
    }
    UpdateOrAddPurchaseItem(requestBody.Items,0,function (success) {
        if(success){
            context.succeed({});
        }else{
            context.fail("Internal server error");
        }
    })
};
UpdateItems.MasterOnly = true;
exports.UpdateItems = interception.Intercept(UpdateItems);