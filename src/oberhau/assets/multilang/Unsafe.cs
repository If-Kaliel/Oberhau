// Static ASP.NET/SqlClient fixture. Never run this code against a database.
using System.Data.SqlClient;
class Unsafe {
  dynamic Request;
  SqlCommand Lookup(SqlConnection connection) {
    string name = Request.QueryString["name"];
    return new SqlCommand("SELECT name FROM accounts WHERE name = '" + name + "'", connection);
  }
}
