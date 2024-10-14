using Microsoft.AspNetCore.Mvc;
using System.Net;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using ATDapi.Responses;
using ATDapi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;

[ApiController]
public class AuthController : ControllerBase
{
    private IConfiguration _configuration;
    private Conexion db= new Conexion();

    public AuthController(IConfiguration configuration)
    {
        this._configuration = configuration;
    }
    
    // Login endpoint
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel model)
    {
        try
        {
            int state = db.Login(model);
            if (state == 1)
            {
                var token = GenerateAccessToken(model.Username);
                return Ok(new { AccessToken = new JwtSecurityTokenHandler().WriteToken(token) });
            }
            else
            {
                return Unauthorized(new { message = "Invalid credentials" });
            }
        }
        catch
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }
    }

    // Signin endpoint
    [HttpPost("signin")]
    public IActionResult Signin([FromBody] LoginModel model)
    {
        try
        {
            int state = db.Signin(model);
            if (state == 1)
            {
                var token = GenerateAccessToken(model.Username);
                return Ok(new { AccessToken = new JwtSecurityTokenHandler().WriteToken(token) });
            }
            else if (state == 2)
            {
                return Conflict(new { message = "User already exists" });
            }
            else
            {
                return BadRequest(new { message = "User creation failed" });
            }
        }
        catch
        {
            return BadRequest(new { message = "User creation failed" });
        }
    }

    // Modify user password endpoint
    [HttpPut("modify")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult ModifyPassword([FromBody] LoginModel model)
    {
        var currentUser = HttpContext.User.Identity.Name;

        if (string.IsNullOrEmpty(currentUser))
        {
            return Unauthorized(new { message = "Unauthorized access" });
        }

        try
        {
            int state = db.Modify(model);
            if (state == 1)
            {
                return Ok(new { message = "Password updated successfully" });
            }
            else
            {
                return BadRequest(new { message = "Password update failed" });
            }
        }
        catch
        {
            return BadRequest(new { message = "Password update failed" });
        }
    }

    // Delete user endpoint
    [HttpDelete("delete")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult DeleteUser([FromBody] LoginModel model)
    {
        var currentUser = HttpContext.User.Identity.Name;

        if (string.IsNullOrEmpty(currentUser))
        {
            return Unauthorized(new { message = "Unauthorized access" });
        }

        try
        {
            int state = db.Delete(model);
            if (state == 1)
            {
                return Ok(new { message = "User deleted successfully" });
            }
            else
            {
                return BadRequest(new { message = "User deletion failed" });
            }
        }
        catch
        {
            return BadRequest(new { message = "User deletion failed" });
        }
    }

    // Generate JWT token
    private JwtSecurityToken GenerateAccessToken(string userName)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, userName)
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(60),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"])),
                SecurityAlgorithms.HmacSha256)
        );

        return token;
    }

    [HttpGet("verify-token")]
    public IActionResult VerifyToken()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

        if (string.IsNullOrEmpty(token))
        {
            return Unauthorized();
        }

        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["JwtSettings:Issuer"],
                ValidAudience = _configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]))
            };

            tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            return Ok();
        }
        catch
        {
            return Unauthorized();
        }
    }
}