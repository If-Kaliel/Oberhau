// Static servlet/JDBC fixture. No compilation or code execution is required.
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;
class Unsafe {
  void lookup(HttpServletRequest request, Statement statement) throws Exception {
    String name = request.getParameter("name");
    statement.executeQuery("SELECT name FROM accounts WHERE name = '" + name + "'");
  }
}
