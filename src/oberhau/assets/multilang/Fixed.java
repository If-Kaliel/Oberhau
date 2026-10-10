// Static JDBC parameterization control.
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
class Fixed {
  void lookup(HttpServletRequest request, Connection connection) throws Exception {
    String name = request.getParameter("name");
    PreparedStatement query = connection.prepareStatement("SELECT name FROM accounts WHERE name = ?");
    query.setString(1, name);
    query.executeQuery();
  }
}
