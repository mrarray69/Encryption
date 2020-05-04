namespace Encryption
{
    using System.Data;
    using System.Data.SqlClient;

    internal class DatabaseLayer
    {
        protected const string _dBConnectionString = "Server=(local);Integrated Security=true;" + "Initial Catalog=AdventureWorks2012";
        protected static string ConnectionString()
        {
            return _dBConnectionString;
        }

        public static DatabaseParam ReturnPassword()
        {
            DatabaseParam databaseParam= new DatabaseParam();
            SqlParameter param = new SqlParameter();

            using (SqlConnection connection = new SqlConnection(ConnectionString()))
            {
                connection.Open();
                SqlCommand command = new SqlCommand("ReturnPass", connection);
                command.CommandType = CommandType.StoredProcedure;
                SqlParameter pass = command.Parameters.Add("@Pass", SqlDbType.NVarChar,4000);
                SqlParameter key = command.Parameters.Add("@Keyy", SqlDbType.NVarChar,4000);
                SqlParameter iv = command.Parameters.Add("@Vi", SqlDbType.NVarChar,4000);
                pass.Direction = ParameterDirection.Output;
                key.Direction = ParameterDirection.Output;
                iv.Direction = ParameterDirection.Output;
                command.ExecuteNonQuery();
                databaseParam._strCiphertext = pass.Value.ToString();
                databaseParam._strIV = iv.Value.ToString();
                databaseParam._strKey = key.Value.ToString();
                connection.Close();
             }
            return databaseParam;
        }

        public static void InsertUpdatePassword(DatabaseParam clsDatabaseParam)
        {


            using (SqlConnection connection = new SqlConnection(ConnectionString()))
            {
                SqlCommand command = new SqlCommand("InsertUpdatePass", connection);
                command.Parameters.AddWithValue("Pass", clsDatabaseParam._strCiphertext);
                command.Parameters.AddWithValue("Keyy", clsDatabaseParam._strKey);
                command.Parameters.AddWithValue("Vi", clsDatabaseParam._strIV);
                command.CommandType = CommandType.StoredProcedure;
                connection.Open();
                command.ExecuteNonQuery();
                connection.Close();


            }

        }
    }
}
