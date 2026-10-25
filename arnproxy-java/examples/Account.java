import com.arnproxy.sdk.Client;
import com.arnproxy.sdk.ApiException;

/** One read-only account request. Key comes only from the environment. */
public final class Account {
 public static void main(String[] args) {
  try {
   var client=new Client(System.getenv("ARNPROXY_API_KEY"));
   var response=client.account();
   System.out.println(response.getAsJsonObject("data").get("id").getAsInt());
  } catch(ApiException error) {
   System.err.println(error.code);
   System.exit(1);
  }
 }
}
