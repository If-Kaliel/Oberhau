// Static SqlClient bound-parameter control.
using System.Data.SqlClient;
class Fixed {
  dynamic Request;
  SqlCommand Lookup(SqlConnection connection) {
    string name = Request.QueryString["name"];
    SqlCommand query = new SqlCommand("SELECT name FROM accounts WHERE name = @name", connection);
    query.Parameters.AddWithValue("@name", name);
    return query;
  }
}
