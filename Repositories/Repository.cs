using Dapper;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.Odbc;
using System.Threading.Tasks;

namespace ATDapi.Repositories;

    public class Repository
    {
        private string dbConnectionString = "DRIVER={ODBC Driver 17 for SQL Server};SERVER=server-terciario.hilet.com,11333;DATABASE=SimpleDB;UID=sa;PWD=1234!\"qwerQW;";
        //Traigo la cadena de conexion que correspona dependiendo del caso de uso dentro del constructor
        public Repository()
        {

        }

        public async Task<int> DeleteAsync(string query)
        {
            using (OdbcConnection connection = new OdbcConnection(dbConnectionString))
            {
                return await connection.ExecuteAsync(query);
            }
        }

        //Query que trae una sola fila de la tabla
        public async Task<T> GetByQuery<T>(string query)
        {
            using (OdbcConnection connection = new OdbcConnection(dbConnectionString))
            {
                return await connection.QueryFirstOrDefaultAsync<T>(query);
            }
        }

        //Query que trae varias filas desde la base de datos
        public async Task<List<T>> GetListBy<T>(string query)
        {
            using (OdbcConnection connection = new OdbcConnection(dbConnectionString))
            {
                IEnumerable<T> rows = await connection.QueryAsync<T>(query);
                return rows.AsList();
            }
        }

        //Query que inserta en la tabla
        public async Task<dynamic> InsertByQuery(string query)
        {
            using (OdbcConnection connection = new OdbcConnection(dbConnectionString))
            {
                try
                {
                    return await connection.ExecuteAsync(query);

                }catch(Exception ex)
                {
                    throw ex;
                }
            }
        }
    }


