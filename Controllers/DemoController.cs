using ATDapi.Responses;
using ATDapi.Models;
using ATDapi.Repositories;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using Microsoft.AspNetCore.Authorization;

namespace ATDapi.Controllers;

//Este es nuestro controller, desde el cual vamos a recibir, procesar y responder todas las peticiones http de esta api de muestra.
//ControllerBase Doc. https://learn.microsoft.com/es-es/aspnet/mvc/overview/older-versions-1/controllers-and-routing/
//Este ultimo link es muy amplio y trata muchos contenidos no tomados en cuenta. Pero puede servirles de guia en caso
//de que quieran profundizar dentro del uso de esta clase
[ApiController]
public class DemoController : ControllerBase
{
    private Repository repository = new Repository();



    //Esta Lista estatica, la vamos a utilizar para almacenar los datos que son enviados y recibidos.
    //Esto debido a que aun no poseemos una conexion con una base de datos.
    //https://learn.microsoft.com/es-es/dotnet/api/system.collections.generic.list-1?view=net-8.0
    public static List<SimpleModel> DataList = new List<SimpleModel>(); 

                    //La siguiente funcion es un endpoint. Las cabeceras nos permiten indicarles como deberian comportarse ante una request.
    [HttpGet]       //Esta primera es el Metodo. Si recordamos la clase sobre protocolo Http, podemos inferir rapidamente cual es su funcion. //Http Methods Doc. https://developer.mozilla.org/es/docs/Web/HTTP/Methods
    [Route("Get")]  //Esta segunda, se utiliza para indicar la ruta en la que va a ser expuesto nuestro endpoint. Si levantamos por ejemplo el servidor en http://localhost:8080. Nuestro endpoint sera accesible en http://localhost:8080/get.
    [Authorize]
    public async Task<BaseResponse> Get()
    {
        string query = SimpleModel.GetAll();
        try
        {
            var rsp = await repository.GetListBy<dynamic>(query);
            return new DataResponse<dynamic>(true, (int)HttpStatusCode.OK, "Lista de entidades", data: rsp);
        }
        catch (Exception ex)
        {
            return new BaseResponse(false, (int)HttpStatusCode.InternalServerError, ex.Message);
        }
    }

    [HttpPost]
    [Route("Post")]
    public async Task<BaseResponse> Post([FromBody]SimpleModel dataInput) //En esta funcion vemos el primer pasaje de informacion desde el frontend al backend. Si recordamos de las clases sobre el protocolo http
    {                                                         //podemos observar que lo que hacemos en el parametro de la funcion es primero indicar el lugar en donde la informacion viaja dentro de la
        dataInput.id = Guid.NewGuid().ToString();             //request '[FromBody]' luego el modelo que esta debe respetar, es decir, la clase 'SimpleModel' y por ultimo el nombre con el cual vamos a poder
        //DataList.Add(dataInput);                            //acceder a esta informacion dentro del ambito de la fucnion 'dataInput'. En sintecis es un pasaje de parametro de funcion, con un pequeno fragmento adicional.
        
        string query = dataInput.InsertByQuery();
        try
        {
            var rsp = await repository.InsertByQuery(query);

            return new DataResponse<dynamic>(true, (int)HttpStatusCode.Created, "Entidad creada correctamente", data: rsp);
        }
        catch(Exception ex)
        {
            return new BaseResponse(false, (int)HttpStatusCode.InternalServerError, ex.Message);
        } 
    }

    [HttpPut]
    [Route("Put")]
    public BaseResponse Put([FromBody]SimpleModel dataInput)
    {
        if(dataInput.id == null)
        {
            return new BaseResponse(false, (int)HttpStatusCode.BadRequest, "El parametro id es requerido");
        }

        SimpleModel? tmp = DataList.FirstOrDefault(x => x.id == dataInput.id);

        if(tmp == null)
        {
            return new BaseResponse(false, (int)HttpStatusCode.NotFound, "El objeto no fue encontrado");
        }
        else
        {
            DataList.Remove(tmp);
            if(dataInput.message != null)
            {
                tmp.message = dataInput.message;
            }

            if(dataInput.number != null)
            {
                tmp.number = dataInput.number;
            }

            DataList.Add(tmp);

            return new BaseResponse(true, (int)HttpStatusCode.OK, "Objeto parcialmente actualizado");
        }
    }

    [HttpPatch]
    [Route("Patch")]
    public BaseResponse Patch([FromBody]SimpleModel dataInput)
    {
        if(dataInput.id == null)
        {
            return new BaseResponse(false, (int)HttpStatusCode.BadRequest, "El parametro id es requerido");
        }

        SimpleModel? tmp = DataList.FirstOrDefault(x => x.id == dataInput.id);

        if(tmp == null)
        {
            return new BaseResponse(false, (int)HttpStatusCode.NotFound, "El objeto no fue encontrado");
        }
        else
        {
            DataList.Remove(tmp);
            DataList.Add(dataInput);

            return new BaseResponse(true, (int)HttpStatusCode.OK, "Objeto actualizado");
        }
    }

    [HttpDelete]
    [Route("Delete")]
    public async Task<BaseResponse> Delete([FromQuery]String id)
    {
        string query = SimpleModel.DeleteByQuery(id);
        try
        {
            var rsp = await repository.DeleteAsync(query);
            return new DataResponse<dynamic>(true, (int)HttpStatusCode.OK, "Objeto elminiado", data: rsp);

        }
        catch(Exception ex)
        {
            return new BaseResponse(false, (int)HttpStatusCode.InternalServerError, ex.Message);
        }
    }
}