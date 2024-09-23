using ATDapi.Models;


namespace ATDapi.Responses;

//Este es el objeto base response, que se utiliza para todas las respuestas formadas ante una request
public class BaseResponse
{
    public bool succes {get; set;}          //Bool que indica si el proceso realizado fue exitoso
    public bool error {get; set;}           //Bool que indica si existio un error en el proceso
    public int code {get; set;}             //Int que almacena el Http Status code de la respuesta //Doc. StatusCodes https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
    public string message {get; set;}       //String donde se envia el mensaje de la respuesta

    public BaseResponse(bool succes, int code, string message)
    {
        this.succes = succes;
        this.error = !succes;
        this.code = code;
        this.message = message;
    }
}

//Este es un objeto que ereda de BaseResponse, que puede ser utilizado para enviar un objeto generico 
//como respuesta, ademas de los campos previamente mencionados.
//Doc. Genericos https://learn.microsoft.com/es-es/dotnet/csharp/fundamentals/types/generics
//Doc. Herencia https://learn.microsoft.com/es-es/dotnet/csharp/fundamentals/tutorials/inheritance
public class DataResponse<T> : BaseResponse
{
    private List<T> dataList;

    public new T data {get; set;} = default;

    public DataResponse(bool succes, int code, string message, T data = default) : base (succes, code, message)
    {
        this.data = data;
    }

    public DataResponse(bool succes, int code, string message, List<T> dataList) : base(succes, code, message)
    {
        this.dataList = dataList;
    }
}
