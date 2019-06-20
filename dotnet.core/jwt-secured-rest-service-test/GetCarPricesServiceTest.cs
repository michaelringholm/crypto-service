using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using com.opusmagus.encryption;
using crypto_service;
using data_transport_layer;
using file_security_vault;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using service_layer;
using Xunit;
using Xunit.Abstractions;

namespace jwt_secured_rest_service_test
{
    // dotnet test --filter Category=IntegrationTest
    public class GetCarPricesServiceTest
    {
        private ITestOutputHelper outputHelper;
        private IConfiguration config;
        private ISecurityVault securityVault;
        private ILogger logger;

        public GetCarPricesServiceTest(ITestOutputHelper outputHelper) {
            this.outputHelper = outputHelper;
            var env = "dev"; //Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            outputHelper.WriteLine($"env={env}");                        
            config = new ConfigurationBuilder().SetBasePath(Directory.GetCurrentDirectory()).AddJsonFile($"appsettings.{env}.json", optional:false, reloadOnChange:true).Build();
            logger = new XUnitLogger(outputHelper);
            securityVault = new FileSecurityVault(logger, config);            
        }

        [Fact]
        [Trait("Category","IntegrationTest")]
        public void Execute()
        {            
            var apiKey = config.GetSection("ApiKey").Value;
            outputHelper.WriteLine($"apiKey={apiKey}");
            WebClient client = new WebClient();
            var jwt = client.DownloadString($"https://cc-dev-jwt-secured-rest-services-fna.azurewebsites.net/api/GetCarPricesService?code={apiKey}");
            outputHelper.WriteLine($"jwt={jwt}");
            var json =  JWTHelper.FromJWTBase64(jwt, logger, securityVault, "commentor.dk", "sym-pw.secret", "sym-salt.secret", "rsa-prv-key-set2.key", "rsa-pub-key-set1.key");
            var carPrices = JsonConvert.DeserializeObject<List<CarPrice>>(json);
            outputHelper.WriteLine($"carPrices.Count={carPrices.Count}");
            outputHelper.WriteLine($"json={json}");
            Assert.Equal(4, carPrices.Count);
            Assert.Equal(100500, carPrices[0].CarId);
            Assert.Equal(325000, carPrices[1].Price);            
        }
    }
}
