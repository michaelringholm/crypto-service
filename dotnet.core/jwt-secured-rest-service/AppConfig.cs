using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Configuration;

namespace commentor.dk
{
    internal class AppConfig
    {
        internal static IConfiguration Create(ExecutionContext context)
        {
            var config = new ConfigurationBuilder()
            .SetBasePath(context.FunctionAppDirectory)
            .AddJsonFile("local.settings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables()
            .Build();

            return config;
        }
    }
}