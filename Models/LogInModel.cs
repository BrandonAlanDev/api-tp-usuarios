using System.ComponentModel.DataAnnotations;

namespace ATDapi.Models;


public class LoginModel
{
    [Required(ErrorMessage = "El nombre de usuario es requerido.")]
    public string Username { get; set; }

    [Required(ErrorMessage = "La contraseña es requerida.")]
    [DataType(DataType.Password)]
    public string Password { get; set; }
}