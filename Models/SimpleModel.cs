namespace ATDapi.Models;

//Esta es una clase simple y servira en este aplicativo como el modelo que utilizaremos, tanto como contrato para recibir
//informacion desde el frontend, como para enviarla dentro del objeto DataResponse.
//Doc. clases https://learn.microsoft.com/es-es/dotnet/csharp/fundamentals/types/classes


public class SimpleModel
{
    public string? id {get; set;}
    public string message {get; set;}
    public int number {get; set;}

    public string InsertByQuery()
    {
        return string.Format("INSERT INTO simple_models VALUES ('{0}', '{1}', {2})", this.id, this.message, this.number);
    }

    public static string GetAll()
    {
        return string.Format("SELECT * FROM simple_models;");
    }

    public static string DeleteByQuery(string id)
    {
        return string.Format("DELETE FROM simple_models WHERE id = '{0}'", id);
    }
}