﻿using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Azure.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using Vnr.IdentityServer;

namespace StsServer
{
    public class Program
    {
        public static int Main(string[] args)
        {
            var seed = args.Any(x => x == "/seed");
            if (seed) args = args.Except(new[] { "/seed" }).ToArray();

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.Console()
                .CreateLogger();

            try
            {
                Log.Information("Starting web host");

                if (seed)
                {
                    var host = CreateHostBuilder(args).Build();

                    SeedData.EnsureSeedData(host.Services);
                    return 0;
                }

                CreateHostBuilder(args).Build().Run();
                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                //.ConfigureAppConfiguration((context, config) =>
                //{
                //    if (context.HostingEnvironment.IsProduction())
                //    {
                //        var builtConfig = config.Build();

                //        using (var store = new X509Store(StoreLocation.CurrentUser))
                //        {
                //            store.Open(OpenFlags.ReadOnly);
                //            var certs = store.Certificates
                //                .Find(X509FindType.FindByThumbprint,
                //                    builtConfig["AzureADCertThumbprint"], false);

                //            config.AddAzureKeyVault(new Uri($"https://{builtConfig["KeyVaultName"]}.vault.azure.net/"),
                //                                    new ClientCertificateCredential(builtConfig["AzureADDirectoryId"], builtConfig["AzureADApplicationId"], certs.OfType<X509Certificate2>().Single()),
                //                                    new KeyVaultSecretManager());

                //            config.AddJsonFile("appsettings.json", optional: false)
                //                    .AddJsonFile($"appsettings.{context.HostingEnvironment.EnvironmentName}.json", optional: true);
                //            store.Close();
                //        }
                //    }
                //})
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>()
                    .UseSerilog((hostingContext, loggerConfiguration) => loggerConfiguration
                    .ReadFrom.Configuration(hostingContext.Configuration)
                    .Enrich.FromLogContext()
                    .WriteTo.File("../Logs/_log_sts.txt")
                    .WriteTo.Console(theme: AnsiConsoleTheme.Code)
                );
                });
    }
}