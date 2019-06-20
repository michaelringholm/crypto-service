using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using business_layer;
using file_security_vault;
using Microsoft.Extensions.Configuration;
using crypto_service;
using com.opusmagus.encryption;

namespace commentor.dk
{
    public static class GetCarPricesService
    {
        [FunctionName("GetCarPricesService")]
        //public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest httpRequest, ILogger logger, IConfiguration config)
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest httpRequest, ILogger logger, ExecutionContext context)
        {
            logger.LogInformation("C# HTTP trigger function processed a request.");            
            var inputData = await GetInputParameters(httpRequest);
            var config = AppConfig.Create(context);

            //if(inputData != null)
                //return (ActionResult)new OkObjectResult($"Hello, {inputData}");
            var carPrices = new GetCarPricesCommand().Execute(null);
            
            var securityVault = new FileSecurityVault(logger, config);
            var jwtBase64 = JWTHelper.ToJWTBase64(carPrices, logger, securityVault, "commentor.dk", "sym-pw.secret", "sym-salt.secret", "rsa-prv-key-set1.key", "rsa-pub-key-set2.key");
            return (ActionResult)new OkObjectResult(jwtBase64);
            
            //return (ActionResult)new OkObjectResult(carPrices);
            //return (ActionResult)new OkObjectResult($"Here is a list of car prices");
            //return new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }        

        private static async Task<dynamic> GetInputParameters(HttpRequest httpRequest)
        {
            string name = httpRequest.Query["name"];
            string requestBody = await new StreamReader(httpRequest.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;
            return name;
        }
    }
}
