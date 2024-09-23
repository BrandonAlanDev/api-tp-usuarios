using System.ComponentModel.DataAnnotations;

namespace ATDapi.Models;


public class Usuario
{
    public string id_usuario { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public int id_tipo { get; set; }
}