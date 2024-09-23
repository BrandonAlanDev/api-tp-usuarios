//Este es nuestro metodo main implicito. Desde la version 7.0 de .NET Core, la funcion main ya no requiere ser declarada,
//pero esto no quiere decir que no exista. Esta sigue funcionando de la misma manera que en las versiones anteriores. Solo
//que ahora esta dentro de este archivo.
//No es necesario profundizar en esto, ya que es un cambio de sintaxis mas que una cuestion funcional. Pero de querer hacerlo
//investiguen 'instrucciones de nivel superior en un archivo como punto de entrada'.
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);


var configuration = new ConfigurationBuilder()
    .SetBasePath(builder.Environment.ContentRootPath)
    .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
    .Build();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["JwtSettings:Issuer"],
            ValidAudience = configuration["JwtSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JwtSettings:SecretKey"]))
        };
    });


//Este es el espacio donde deberemos de construir los servicios que luego expondra nuestra API.
//por ahora el unico que agregaremos es el servicio de Cors Policy ya visto anteriormente en clase.
//pero tengan en cuenta que las politicas de autenticacion deberan ser declaradas en este espacio para
//futuros proyectos que lo requieran. No es necesario que toquen este archivo.
builder.Services.AddCors(options => 
    {
        options.AddDefaultPolicy(policy => {
            policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin();
        });
    }
);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
//Aca termina el espacio de construccion de servicios.



var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.UseCors();
app.Run();
