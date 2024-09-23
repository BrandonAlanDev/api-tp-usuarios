using Dapper;
using Microsoft.Data.SqlClient;
using System.Data;
using BCrypt.Net;
namespace ATDapi.Models;


public class Conexion
{
    private string _connectionString = "Data Source=server-terciario.hilet.com,11333;Database=usuariosbrandon;Integrated Security=false;User ID=sa;Password=1234!\"qwerQW;Encrypt=True;TrustServerCertificate=True;";

    /**
    *
    @STATEMENT INT = 0,
	@ID_USUARIO INT = 0,
	@USERNAME VARCHAR(20) =NULL,
	@PASSWORD VARCHAR(30) =NULL,
	@ID_TIPO INT = 2
    *
    STATEMENTS :
        1 : Select de password, te pide el usuario
        2 : Delete de usuarios, te pide usuario
        3 : Update de contraseña del usuarios, te pide el usuario y la contraseña
        4 : Count de usuarios segun username, te pide username
        5 : Insert de usuarios , te pide username y password
    */

    /*  Login le paso un modelo de usuario y matchea
    *   Return 0 : No coincide
    *   Return 1 : Coincide
    */
    public int Login(LoginModel model)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                try{
                connection.Open();
                var parameters = new
                {
                    STATEMENT = 1,
                    USERNAME = model.Username
                };
                var passwordHash = connection.QuerySingleOrDefault<string>(
                    "dbo.CRUD_usuarios",
                    parameters,
                    commandType: CommandType.StoredProcedure
                );

                if (passwordHash == null)
                {
                    return 0;
                }
                //if (BCrypt.Net.BCrypt.Verify(model.Password, passwordHash))
                if (model.Password == passwordHash)
                {
                    return 1;
                }else{ return 0; }
                }catch(Exception ex){Console.WriteLine(ex); return 0;}
            }
        }

    /*  Sign in le paso un modelo de usuario y crea
    *   Return 0 : no se pudo crear
    *   Return 1 : se creo
    *   Return 2 : ya existe el usuario
    */
    public int Signin(LoginModel model)
    {
        try
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();

                // Paso 1: Verificar si el usuario ya existe
                var checkParameters = new
                {
                    STATEMENT = 4,
                    USERNAME = model.Username
                };

                var userCount = connection.QuerySingle<int>(
                    "dbo.CRUD_usuarios",
                    checkParameters,
                    commandType: CommandType.StoredProcedure
                );
                if (userCount > 0)
                {
                    return 2;
                }
                // Paso 2: Crear el usuario
                var passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);
                var insertParameters = new
                {
                    STATEMENT = 5,
                    USERNAME = model.Username,
                    PASSWORD = passwordHash
                };

                return connection.Execute(
                    "dbo.CRUD_usuarios",
                    insertParameters,
                    commandType: CommandType.StoredProcedure
                );
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error en Signin: {ex.Message}");
            throw;
        }
    }


    /* Modify le paso un modelo de usuario y lo modifica
    *   Return 0 : No se logro modificar
    *   Return 1 : Se modifico
    */
    public int Modify(LoginModel model)
    {
        using (var connection = new SqlConnection(_connectionString))
        {
            connection.Open();

            var passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);

            var parameters = new
            {
                STATEMENT = 3,
                USERNAME = model.Username,
                PASSWORD = passwordHash
            };

            return connection.Execute(
                "dbo.CRUD_usuarios",
                parameters,
                commandType: CommandType.StoredProcedure
            );
        }
    }

    /* Delete le paso un modelo de usuario y lo elimina
    *   Return 0 : No se logró eliminar
    *   Return 1 : Se elimino correctamente
    */
    public int Delete(LoginModel model)
    {
        using (var connection = new SqlConnection(_connectionString))
        {
            connection.Open();

            var parameters = new
            {
                STATEMENT = 2,
                USERNAME = model.Username
            };

            return connection.Execute(
                "dbo.CRUD_usuarios",
                parameters,
                commandType: CommandType.StoredProcedure
            );
        }
    }
}