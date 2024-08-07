const XDCValidator = require("../artifacts/contracts/XDCValidator.sol/XDCValidator.json");
const fs = require("fs");

const abi = XDCValidator["abi"];
const bytecode = XDCValidator["bytecode"];

fs.writeFile("./abi", JSON.stringify(abi, null, 3), "utf8", function (error) {
  if (error) {
    console.log(error);
    return false;
  }
  console.log("Write success ");
});
fs.writeFile("./bytecode", bytecode, "utf8", function (error) {
  if (error) {
    console.log(error);
    return false;
  }
  console.log("Write success ");
});
