using System.ComponentModel.DataAnnotations;

namespace ATDapi.Models;
public class RefreshTokenModel
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
}
