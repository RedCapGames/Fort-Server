﻿var interception = require("./Interception/Intercept.js");

exports.GetIabPackages = interception.Intercept(function (requestBody, context) {
    var x = requestBody.x;
    var y = requestBody.y;

    context.log("First number = " + x);
    context.log("Second number = " + y);
    context.log("Answer = " + (x + y));
    context.succeed(x + y);
});

exports.PurchaseIabPackage = interception.Intercept(function (requestBody, context) {
    var x = requestBody.x;
    var y = requestBody.y;

    context.log("First number = " + x);
    context.log("Second number = " + y);
    context.log("Answer = " + (x + y));
    context.succeed(x + y);
});

exports.GetGamePurchasableItems = interception.Intercept(function (requestBody, context) {
    var x = requestBody.x;
    var y = requestBody.y;

    context.log("First number = " + x);
    context.log("Second number = " + y);
    context.log("Answer = " + (x + y));
    context.succeed(x + y);
});

exports.PurchaseGamePurchasableItem = interception.Intercept(function (requestBody, context) {
    var x = requestBody.x;
    var y = requestBody.y;

    context.log("First number = " + x);
    context.log("Second number = " + y);
    context.log("Answer = " + (x + y));
    context.succeed(x + y);
});

exports.GetPurchasedGamePurchasableItems = interception.Intercept(function (requestBody, context) {
    var x = requestBody.x;
    var y = requestBody.y;

    context.log("First number = " + x);
    context.log("Second number = " + y);
    context.log("Answer = " + (x + y));
    context.succeed(x + y);
});