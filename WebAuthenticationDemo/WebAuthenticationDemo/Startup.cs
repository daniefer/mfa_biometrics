using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using WebAuthenticationDemo.Business;
using WebAuthenticationDemo.Business.Algorithums;

namespace WebAuthenticationDemo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = true;
            services.AddSingleton<CredentialManager>();
            services.AddTransient<AttestationParser>();
            services.AddTransient<AuthDataParser>();
            services.AddTransient<CredentialPublicKeyParser>();
            services.AddTransient<PublicKeyFactory>();

            services.AddControllers();
            services.AddAuthorization(config =>
            {
                config.AddPolicy("default", new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
            });
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => { 
                    options.RequireHttpsMetadata = false; 
                    options.SaveToken = true; 
                    options.TokenValidationParameters = new TokenValidationParameters 
                    { 
                        ValidateIssuer = true, 
                        ValidateAudience = true, 
                        ValidateLifetime = true, 
                        ValidateIssuerSigningKey = true, 
                        ValidIssuer = Configuration["Jwt:Issuer"], 
                        ValidAudience = Configuration["Jwt:Audience"], 
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"])), 
                        ClockSkew = TimeSpan.Zero 
                    }; 
                });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if(env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }
            //app.UseHttpsRedirection();
            app.UseCors(builder =>
            {
                builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
            });
            app.UseExceptionHandler(config =>
            {
                config.Run(async context =>
                {
                    context.Response.ContentType = "application/json";
                    var exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();

                    if (exceptionHandlerPathFeature?.Error is BadRequestException badRequest)
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new { error = badRequest.Message }));
                        return;
                    }
                    context.Response.StatusCode = 500;
                    await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new { error = "Unknown error" }));
                    return;
                });
            });
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}
