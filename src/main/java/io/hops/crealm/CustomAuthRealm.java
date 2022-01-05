package io.hops.crealm;

import com.sun.appserv.connectors.internal.api.ConnectorRuntime;
import com.sun.appserv.security.AppservRealm;
import com.sun.enterprise.security.auth.digest.api.Password;
import com.sun.enterprise.security.auth.realm.BadRealmException;
import com.sun.enterprise.security.auth.realm.IASRealm;
import com.sun.enterprise.security.auth.realm.InvalidOperationException;
import com.sun.enterprise.security.auth.realm.NoSuchRealmException;
import com.sun.enterprise.security.auth.realm.NoSuchUserException;
import com.sun.enterprise.security.common.Util;
import com.sun.enterprise.universal.GFBase64Encoder;
import com.sun.enterprise.util.Utility;
import com.yubico.base.Pof;
import com.yubico.base.Token;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NamingException;
import javax.security.auth.login.LoginException;
import org.jvnet.hk2.annotations.Service;
import javax.sql.DataSource;
import org.apache.commons.codec.binary.Base32;
import org.glassfish.hk2.api.ActiveDescriptor;
import org.glassfish.hk2.api.MultiException;
import org.glassfish.hk2.utilities.BuilderHelper;

@Service(name = "CustomAuthRealm")
public class CustomAuthRealm extends AppservRealm {

  /**
   * Adapted from
   * http://grepcode.com/file/repo1.maven.org/maven2/org.glassfish.security/security/3.0.1/com/sun/enterprise/security/auth/realm/jdbc/JDBCRealm.java
   * and
   * https://weblogs.java.net/blog/evanx/archive/2012/11/07/google-authenticator-thus-enabled
   * and https://code.google.com/p/yubikey-server-j/
   */

  /*
   * TOTP default time interval
   */
  public static final long KEY_VALIDATION_INTERVAL_MS
          = TimeUnit.SECONDS.toMillis(30);

  public static final int SECRET_KEY_MODULE = 1000 * 1000;

  // Descriptive string of the authentication type of this realm.
  public static final String AUTH_TYPE = "cauth";
  public static final String PRE_HASHED = "HASHED";
  public static final String PARAM_DATASOURCE_JNDI = "datasource-jndi";

  public static final String PARAM_DIGEST_ALGORITHM = "digest-algorithm";
  public static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";
  public static final String NONE = "none";

  public static final String PARAM_ENCODING = "encoding";
  public static final String HEX = "hex";
  public static final String BASE64 = "base64";
  public static final String DEFAULT_ENCODING = HEX; // for digest only

  public static final String PARAM_CHARSET = "charset";

  public static final String PARAM_USER_TABLE = "user-table";
  public static final String PARAM_USER_NAME_COLUMN = "user-name-column";
  public static final String PARAM_PASSWORD_COLUMN = "password-column";
  public static final String PARAM_OTP_COLUMN = "otp-secret-column"; // for the one time password
  public static final String PARAM_TWO_FACTOR_COLUMN = "two-factor-column";
  public static final String PARAM_USER_ACCOUNT_TYPE_COLUMN = "user-account-type-column";
  public static final String PARAM_GROUP_TABLE = "group-table";
  public static final String PARAM_GROUP_NAME_COLUMN = "group-name-column";
  public static final String PARAM_GROUP_TABLE_USER_NAME_COLUMN
          = "group-table-user-name-column";
  public static final String PARAM_USER_STATUS = "user-status-column";
  public static final String PARAM_YUBIKEY_TABLE = "yubikey-table";

  public static final String PARAM_VARIABLES_TABLE = "variables-table";

  /*
   * public static final String PARAM_YUBIKEY_ID_COLUMN = "yubikey-id-column";
   * public static final String PARAM_YUBIKEY_SECRET_COLUMN =
   * "yubikey-secret-column";
   * public static final String PARAM_YUBIKEY_STATUS = "yubikey-status-column";
   * public static final String PARAM_YUBIKEY_USERID_COLUMN =
   * "yubikey-userid-column";
   * public static final String PARAM_YUBIKEY_COUNTER_COLUMN =
   * "yubikey-counter-column";
   * public static final String PARAM_YUBIKEY_SESSION_COLUMN =
   * "yubikey-session-column";
   * public static final String PARAM_YUBIKEY_HIGH_COLUMN =
   * "yubikey-high-column";
   * public static final String PARAM_YUBIKEY_LOW_COLUMN = "yubikey-low-column";
   */
  private static final char[] HEXADECIMAL = {'0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  private Map<String, Vector> groupCache;
  private Vector<String> emptyVector;
  private String passwordQuery = null;
  private String groupQuery = null;
  private String yubikeyUpdateQuery = null;
  private String selectYubikey = null;

  private String selectAuthMethod = null;
  private String selectTwoFactorExcludes = null;

  private MessageDigest md = null;
  Properties prop = null;

  private ActiveDescriptor<ConnectorRuntime> cr;

  @Override
  public String getAuthType() {
    return AUTH_TYPE; //To change body of generated methods, choose Tools | Templates.
  }

  /**
   *
   * @param props
   * @throws BadRealmException
   * @throws NoSuchRealmException
   */
  @Override
  public synchronized void init(Properties props)
          throws BadRealmException, NoSuchRealmException {
    super.init(props);
    String jaasCtx = props.getProperty(IASRealm.JAAS_CONTEXT_PARAM);
    String dsJndi = props.getProperty(PARAM_DATASOURCE_JNDI);
    String digestAlgorithm = props.getProperty(PARAM_DIGEST_ALGORITHM,
            DEFAULT_DIGEST_ALGORITHM);
    String encoding = props.getProperty(PARAM_ENCODING);
    String charset = props.getProperty(PARAM_CHARSET);
    String userTable = props.getProperty(PARAM_USER_TABLE);
    String userNameColumn = props.getProperty(PARAM_USER_NAME_COLUMN);
    String passwordColumn = props.getProperty(PARAM_PASSWORD_COLUMN);
    String otpColumn = props.getProperty(PARAM_OTP_COLUMN);
    String twoFactorColumn = props.getProperty(PARAM_TWO_FACTOR_COLUMN);
    String userAccountType = props.getProperty(PARAM_USER_ACCOUNT_TYPE_COLUMN);
    String groupTable = props.getProperty(PARAM_GROUP_TABLE);
    String groupNameColumn = props.getProperty(PARAM_GROUP_NAME_COLUMN);
    String groupTableUserNameColumn = props.getProperty(
            PARAM_GROUP_TABLE_USER_NAME_COLUMN, userNameColumn);
    String userActiveColumn = props.getProperty(PARAM_USER_STATUS);
    String yubikeyTable = props.getProperty(PARAM_YUBIKEY_TABLE);

    String variablesTable = props.getProperty(PARAM_VARIABLES_TABLE);

    /*
     * String yubikeyId = props.getProperty(PARAM_YUBIKEY_ID_COLUMN);
     * String yubikeyStatus = props.getProperty(PARAM_YUBIKEY_STATUS);
     * String yubikeyUid = props.getProperty(PARAM_YUBIKEY_USERID_COLUMN);
     * String yubikeyHigh = props.getProperty(PARAM_YUBIKEY_HIGH_COLUMN);
     * String yubikeyLow = props.getProperty(PARAM_YUBIKEY_LOW_COLUMN);
     * String yubikeySecret = props.getProperty(PARAM_YUBIKEY_SECRET_COLUMN);
     * String yubikeySessionUse =
     * props.getProperty(PARAM_YUBIKEY_SESSION_COLUMN);
     * String yubikeySessionCounter =
     * props.getProperty(PARAM_YUBIKEY_COUNTER_COLUMN);
     */
    cr = (ActiveDescriptor<ConnectorRuntime>) Util.getDefaultHabitat().
            getBestDescriptor(BuilderHelper.createContractFilter(
                            ConnectorRuntime.class.getName()));

    if (jaasCtx == null) {
      String msg = sm.getString(
              "realm. missing JaaS context", IASRealm.JAAS_CONTEXT_PARAM,
              "CustomAuthRealm");
      throw new BadRealmException(msg);
    }

    if (dsJndi == null) {
      String msg = sm.getString(
              "realm. missing data source ", PARAM_DATASOURCE_JNDI,
              "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (userTable == null) {
      String msg = sm.getString(
              "realm. missing user table", PARAM_USER_TABLE, "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (groupTable == null) {
      String msg = sm.getString(
              "realm.missing gprop table", PARAM_GROUP_TABLE, "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (userNameColumn == null) {
      String msg = sm.getString(
              "realm. missing username columns", PARAM_USER_NAME_COLUMN,
              "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (passwordColumn == null) {
      String msg = sm.getString(
              "realm. missing prop", PARAM_PASSWORD_COLUMN, "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (groupNameColumn == null) {
      String msg = sm.getString(
              "realm. missing prop", PARAM_GROUP_NAME_COLUMN, "CustomAuthRealm");
      throw new BadRealmException(msg);
    }
    if (yubikeyTable == null) {
      yubikeyTable = "yubikey";
    }
    if (twoFactorColumn == null) {
      String msg = sm.getString("realm. missing prop", PARAM_TWO_FACTOR_COLUMN, "CustomAuthRealm");
      throw new BadRealmException(msg);
    }

    passwordQuery = "SELECT " + passwordColumn + " , " + otpColumn + " , "
            + userActiveColumn + "," + twoFactorColumn + ", " + userAccountType + " FROM " + userTable
            + " WHERE " + userNameColumn + " = ?";

    groupQuery = "SELECT " + groupNameColumn + " FROM " + groupTable
            + " WHERE " + groupTableUserNameColumn + " = ?";

    yubikeyUpdateQuery = "UPDATE " + yubikeyTable
            + " SET accessed = ?, counter = ?, "
            + "high = ?, low = ?, session_use = ? WHERE public_id = ?";

    selectYubikey = "SELECT * FROM " + yubikeyTable + " WHERE public_id = ?";

    selectAuthMethod = "SELECT value FROM " + variablesTable
            + " WHERE id = 'twofactor_auth'";

    selectTwoFactorExcludes = "SELECT value FROM " + variablesTable
            + " WHERE id = 'twofactor-excluded-groups'";
    
    if (!NONE.equalsIgnoreCase(digestAlgorithm)) {
      try {
        md = MessageDigest.getInstance(digestAlgorithm);
      } catch (NoSuchAlgorithmException e) {
        String msg = sm.getString("cauth realm does not support digest alg",
                digestAlgorithm);
        throw new BadRealmException(msg);
      }
    }
    if (md != null && encoding == null) {
      encoding = DEFAULT_ENCODING;
    }

    this.setProperty(IASRealm.JAAS_CONTEXT_PARAM, jaasCtx);
    this.setProperty(PARAM_DATASOURCE_JNDI, dsJndi);
    this.setProperty(PARAM_DIGEST_ALGORITHM, digestAlgorithm);
    if (encoding != null) {
      this.setProperty(PARAM_ENCODING, encoding);
    }
    if (charset != null) {
      this.setProperty(PARAM_CHARSET, charset);
    }

    if (_logger.isLoggable(Level.FINEST)) {
      _logger.log(Level.FINEST, "CustomAuthRealm : "
              + IASRealm.JAAS_CONTEXT_PARAM + "= {0}" + ", "
              + PARAM_DATASOURCE_JNDI + " = {1}" + ", " + PARAM_DIGEST_ALGORITHM
              + " = {2}" + ", " + PARAM_ENCODING + " = {3}"
              + ", " + PARAM_CHARSET + " = {4}", new Object[]{jaasCtx, dsJndi,
                digestAlgorithm, encoding, charset});
    }

    groupCache = new HashMap<>();
    emptyVector = new Vector<>();

  }

  @Override
  public Enumeration getGroupNames(String username)
          throws InvalidOperationException, NoSuchUserException {
    Vector vector = groupCache.get(username);
    if (vector == null) {
      String[] grps = findGroups(username);
      setGroupNames(username, grps);
      vector = groupCache.get(username);
    }
    return vector.elements();
  }

  private String[] findGroups(String user) {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    try {
      connection = getConnection();
      _logger.log(Level.FINE, "CAuth acquired connection to DB");
      statement = connection.prepareStatement(groupQuery);
      statement.setString(1, user);
      rs = statement.executeQuery();
      final List<String> groups = new ArrayList<>();
      while (rs.next()) {
        groups.add(rs.getString(1));
      }
      _logger.log(Level.FINE, "CAuth found num groups for user: " + groups.size());
      final String[] groupArray = new String[groups.size()];
      return groups.toArray(groupArray);
    } catch (LoginException | SQLException ex) {
      _logger.log(Level.SEVERE, "CAuth realm group error", user);
      _logger.log(Level.SEVERE, "CAuth realm group error running query: ", groupQuery);
      
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot load group", ex + " query: "+ groupQuery);
      }
      return null;
    } finally {
      close(connection, statement, rs);
    }
  }

  private void setGroupNames(String username, String[] groups) {
    Vector<String> v = null;

    if (groups == null) {
      v = emptyVector;

    } else {
      v = new Vector<>(groups.length + 1);
      for (String group : groups) {
        v.add(group);
      }
    }

    synchronized (this) {
      groupCache.put(username, v);
    }
  }

  /**
   * Start Authentication
   * <p>
   *
   * @param username
   * @param password
   * @return
   */
  public String[] authenticate(String username, String password) {

    String[] groups = null;


    _logger.log(Level.FINEST, "Authenticating: " + username);

    // make a yubikey otp check
    if (password.endsWith(AuthenticationConstants.YUBIKEY_USER_MARKER)) {
      String hpwd = password.substring(0, password.length()
              - AuthenticationConstants.YUBIKEY_USER_MARKER.length());
      if (isValidYubikeyUser(username, hpwd)) {
        groups = findGroups(username);
        groups = addAssignGroups(groups);
        setGroupNames(username, groups);
      } 
    } else if (isValidMobileUser(username, password)) {
      _logger.log(Level.FINEST, "Validated mobile login for: {0}", username);
      groups = findGroups(username);
      groups = addAssignGroups(groups);
      setGroupNames(username, groups);
    } 

    return groups;
  }

  private Connection getConnection() throws LoginException {

    final String dsJndi = this.getProperty(PARAM_DATASOURCE_JNDI);
    try {
//      String nonTxJndiName = dsJndi + "__nontx";
      /*
       * InitialContext ic = new InitialContext();
       * final DataSource dataSource =
       * //V3 Commented
       * (DataSource)ConnectorRuntime.getRuntime().lookupNonTxResource(dsJndi,false);
       * //replacement code suggested by jagadish
       * (DataSource)ic.lookup(nonTxJndiName);
       */
      ConnectorRuntime connectorRuntime = Util.getDefaultHabitat().
              getServiceHandle(cr).getService();
      final DataSource dataSource
              = (DataSource) connectorRuntime.lookupNonTxResource(dsJndi, false);

      //(DataSource)ConnectorRuntime.getRuntime().lookupNonTxResource(dsJndi,false);
      return dataSource.getConnection();
    } catch (MultiException | NamingException | SQLException ex) {
      String msg = sm.getString("CAuth realm cant connect", dsJndi);
      LoginException loginEx = new LoginException(msg);
      loginEx.initCause(ex);
      throw loginEx;
    }

  }

  /**
   * Yubikey Authenticator *
   */
  /**
   * Validate the OTP generated by the Yubikey device.
   * <p>
   * @param public_id
   * @param otp
   * @return
   */
  private boolean validateOTP(String public_id, String otp) {

    Connection conn = null;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    boolean valid = false;
    try {
      conn = getConnection();
      stmt = conn.prepareStatement(selectYubikey);

      stmt.setString(1, public_id);
      rs = stmt.executeQuery();

      if (!rs.first()) {
        return valid;
      }
      
      String secret = rs.getString("aes_secret");

      int seenSessionCounter = rs.getInt("counter");

      int seenLo = rs.getInt("low");

      int seenHi = rs.getInt("high");

      int seenSessionUse = rs.getInt("session_use");

      Token t;
      t = Pof.parse(otp, hexStringToByteArray(secret));
      int sessionCounter = toInt(t.getSessionCounter());
      int scDiff = seenSessionCounter - sessionCounter;

      int sessionUse = t.getTimesUsed();
      int suDiff = seenSessionUse - sessionUse;

      int hi = t.getTimestampHigh() & 0xff;
      int hiDiff = seenHi - hi;

      int lo = toInt(t.getTimestampLow());
      int loDiff = seenLo - lo;

      if (scDiff > 0) {
        return valid;
      }
      if (scDiff == 0 && suDiff > 0) {
        return valid;
      }
      if (scDiff == 0 && suDiff == 0 && hiDiff > 0) {
        return valid;
      }
      if (scDiff == 0 && suDiff == 0 && hiDiff == 0 && loDiff > 0) {
        return valid;
      }
      if (scDiff == 0 && suDiff == 0 && hiDiff == 0 && loDiff == 0) {
        return valid;
      }
   

      valid = updateYubikeyOnTokenId(sessionCounter, hi, lo, sessionUse,
              public_id);
    } catch (SQLException | GeneralSecurityException ex) {
      _logger.log(Level.FINE, "Cannot validate OTP Yubikey", ex);

      return false;
    } finally {
      close(conn, stmt, rs);
    }

    return valid;
  }

  public int toInt(byte[] arr) {
    int low = arr[0] & 0xff;
    int high = arr[1] & 0xff;
    return (int) (high << 8 | low);
  }

  /**
   * Update the Yubikey table after each use of OTP.
   * <p>
   * @param sessionCounter
   * @param hi
   * @param lo
   * @param sessionUse
   * @param public_id
   * @return
   */
  private boolean updateYubikeyOnTokenId(int sessionCounter, int hi, int lo,
          int sessionUse, String public_id) {

    Connection conn = null;
    PreparedStatement stmt = null;
    ResultSet rs = null;
    try {

      conn = getConnection();

      stmt = conn.prepareStatement(yubikeyUpdateQuery);

      stmt.setTimestamp(1, getCurrentTimeStamp());
      stmt.setInt(2, sessionCounter);
      stmt.setInt(3, hi);
      stmt.setInt(4, lo);
      stmt.setInt(5, sessionUse);
      stmt.setString(6, public_id);
      int num = stmt.executeUpdate();
      if (num != 1) {
        throw new SQLException("Internal Yubikey table update error!");
      }
      
    } catch (SQLException | LoginException ex) {
      _logger.log(Level.SEVERE,
              "Cannot update Yubikey table.", ex);

      return false;
    } finally {
      close(conn, stmt, rs);
    }

    return true;
  }

  private byte[] hexStringToByteArray(String encoded) {
    if ((encoded.length() % 2) != 0) {
      throw new IllegalArgumentException(
              "Input string must contain an even number of characters");
    }

    final byte result[] = new byte[encoded.length() / 2];
    final char enc[] = encoded.toCharArray();

    for (int i = 0; i < enc.length; i += 2) {
      StringBuilder curr = new StringBuilder(2);
      curr.append(enc[i]).append(enc[i + 1]);
      result[i / 2] = (byte) Integer.parseInt(curr.toString(), 16);
    }
    return result;
  }

  /**
   * Get the password from the frontend and validate it.
   * <p>
   * @param user
   * @param password
   * @return
   */
  private boolean isValidYubikeyUser(String user, String password) {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    boolean valid = false;

    try {

      // Get the original password
      String hpwd = hashPassword(password.substring(0, password.length() - 44));

      // Get the 44 digit OTP code
      String otpCode = password.substring(password.length() - 44).toLowerCase();

      int len = otpCode.length();
      int split = len - 32;
      
      // Get connedcted to DB and find the user
      connection = getConnection();

      statement = connection.prepareStatement(passwordQuery);

      statement.setString(1, user);
      rs = statement.executeQuery();

      String pwd = null;
      if (rs.next()) {
        // Get the user's credentials
        pwd = rs.getString(1);
        valid = pwd.equalsIgnoreCase(hpwd) && validateOTP(otpCode.substring(0, 12), otpCode.substring(split));
      }
    } catch (SQLException ex) {
      _logger.log(Level.SEVERE, "CAuth realm invalid Yubikey user step 5", new String[]{user, ex.toString()});
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot validate Yubkiey user", ex);
      }
      return false;
    } catch (CharacterCodingException | LoginException | NumberFormatException ex) {
      _logger.log(Level.SEVERE, "CAuth realm invalid Yubikey user", user);
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot validate Yubikeu user", ex);
      }
      return false;
    } finally {
      close(connection, statement, rs);
    }
    return valid;
  }

  /**
   * Mobile Authenticator *
   */
  /**
   * Get the password from the frontend and validate it.
   * <p>
   * @param user
   * @param password
   * @return
   */
  private boolean isValidMobileUser(String user, String password) {
    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;

    boolean valid = false;
    String mode = "false";
    String excludeList = "";
    
    try {

      // Get the original password
      String hpwd = hashPassword(password.substring(0, password.length()
              - AuthenticationConstants.MOBILE_OTP_PADDING.length()));

      // Get the 6 digit OTP code
      String otpCode = password.substring(password.length()
              - AuthenticationConstants.MOBILE_OTP_PADDING.length());

      // Get connedcted to DB and find the user
      connection = getConnection();
      statement = connection.prepareStatement(passwordQuery);
      statement.setString(1, user);
      rs = statement.executeQuery();
      String pwd = null;
      if (rs.next()) {
        // Get the user's credentials
        pwd = rs.getString(1);
        String otp = rs.getString(2);
        //int status = Integer.parseInt(rs.getString(3));
        boolean twoFactorEnabled = rs.getBoolean(4);
        int accountType = rs.getInt(5);

        rs.close();
        statement.close();

        // get the auth mode for two factor auth
        statement = connection.prepareStatement(selectAuthMethod);

        rs = statement.executeQuery();

        if (rs.next()) {
          mode = rs.getString(1);
        }
        
        rs.close();
        statement.close();
        
        statement = connection.prepareStatement(selectTwoFactorExcludes);
        rs = statement.executeQuery();

        if (rs.next()) {
          excludeList = rs.getString(1);
        }
        String[] excludedGroupList = (excludeList != null? excludeList.split(";") : null);
        boolean exclude = isInExcludeList(user, excludedGroupList);
  
        boolean otpNotRequired =
          accountType != 0 || (!mode.equals("mandatory") && (mode.equals("false") || !twoFactorEnabled));
        if (exclude || otpNotRequired) {
          valid = pwd.equalsIgnoreCase(hpwd);
        } else {
          if (HEX.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
            valid = pwd.equalsIgnoreCase(hpwd) && verifyCode(otp, Integer.parseInt(otpCode), getTimeIndex(), 5);
          } else {
            valid = pwd.equalsIgnoreCase(hpwd) && verifyCode(otp, Integer.parseInt(otpCode.trim()), getTimeIndex(), 5);
          }
        }
      }
    } catch (SQLException ex) {
      _logger.log(Level.SEVERE, "CAuth realm invalid user reason: mobile", new String[]{user, ex.toString()});
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot validate mobile user", ex);
      }
      return false;
    } catch (CharacterCodingException | LoginException | NumberFormatException |
            NoSuchAlgorithmException | InvalidKeyException ex) {
      _logger.log(Level.SEVERE, "CAuth realm mobile user char encoding or authentication mode is set wrong.", user);
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot validate mobile user", ex);
      }
      return false;
    } finally {
      close(connection, statement, rs);
    }
    return valid;
  }

  private Password getPassword(String username) {

    Connection connection = null;
    PreparedStatement statement = null;
    ResultSet rs = null;
    boolean valid = false;

    try {
      connection = getConnection();
      statement = connection.prepareStatement(passwordQuery);
      statement.setString(1, username);
      rs = statement.executeQuery();

      if (rs.next()) {
        // Split the merged password and otp
        final String pwd = rs.getString(1);
        final String otp = rs.getString(2).trim();
        if (!PRE_HASHED.equalsIgnoreCase(getProperty(PARAM_ENCODING))) {
          return new Password() {

            @Override
            public byte[] getValue() {
              return pwd.getBytes();
            }

            @Override
            public int getType() {
              return Password.PLAIN_TEXT;
            }

          };
        } else {
          return new Password() {

            @Override
            public byte[] getValue() {
              return pwd.getBytes();
            }

            @Override
            public int getType() {
              return Password.HASHED;
            }

          };
        }
      }
    } catch (LoginException | SQLException ex) {
      _logger.log(Level.SEVERE, "cauth realm invalid user", username);
      if (_logger.isLoggable(Level.FINE)) {
        _logger.log(Level.FINE, "Cannot validate user", ex);
      }
    } finally {
      close(connection, statement, rs);
    }
    return null;

  }

  public static boolean verifyCode(String secret, long code, long timeIndex,
          int variance)
          throws NoSuchAlgorithmException, InvalidKeyException {
    Base32 codec = new Base32();
    byte[] decodedKey = codec.decode(secret);
    for (int i = -variance; i <= variance; i++) {
      if (getCode(decodedKey, timeIndex + i) == code) {
        return true;
      }
    }
    return false;
  }

  public static long getTimeIndex() {
    return System.currentTimeMillis() / 1000 / 30;
  }

  /**
   * Generate the otp code according to some definitions.
   *
   * @param secret
   * @param timeIndex
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   */
  private static long getCode(byte[] secret, long timeIndex)
          throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
    ByteBuffer buffer = ByteBuffer.allocate(8);
    buffer.putLong(timeIndex);
    byte[] timeBytes = buffer.array();
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(signKey);
    byte[] hash = mac.doFinal(timeBytes);
    int offset = hash[19] & 0xf;
    long truncatedHash = hash[offset] & 0x7f;
    for (int i = 1; i < 4; i++) {
      truncatedHash <<= 8;
      truncatedHash |= hash[offset + i] & 0xff;
    }
    return (truncatedHash %= 1000000);
  }

  public String getTimeStamp() {
    SimpleDateFormat sdf
            = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'SSSS");
    Date tmp = new Date();
    return sdf.format(tmp);
  }

  private String hashPassword(String password)
          throws CharacterCodingException {
    char[] pass = password.toCharArray();
    byte[] bytes = null;
    char[] result = null;
    String charSet = getProperty(PARAM_CHARSET);
    bytes = Utility.convertCharArrayToByteArray(pass, charSet);

    if (md != null) {
      synchronized (md) {
        md.reset();
        bytes = md.digest(bytes);
      }
    }

    String encoding = getProperty(PARAM_ENCODING);
    if (HEX.equalsIgnoreCase(encoding)) {
      result = hexEncode(bytes);
    } else if (BASE64.equalsIgnoreCase(encoding)) {
      result = base64Encode(bytes).toCharArray();
    } else { // no encoding specified                                                                                                                                
      result = Utility.convertByteArrayToCharArray(bytes, charSet);
    }
    return String.valueOf(result);
  }

  private char[] hexEncode(byte[] bytes) {
    StringBuilder sb = new StringBuilder(2 * bytes.length);
    for (int i = 0; i < bytes.length; i++) {
      int low = (int) (bytes[i] & 0x0f);
      int high = (int) ((bytes[i] & 0xf0) >> 4);
      sb.append(HEXADECIMAL[high]);
      sb.append(HEXADECIMAL[low]);
    }
    char[] result = new char[sb.length()];
    sb.getChars(0, sb.length(), result, 0);
    return result;
  }

  private String base64Encode(byte[] bytes) {
    GFBase64Encoder encoder = new GFBase64Encoder();
    return encoder.encode(bytes);
  }

  private void close(Connection conn, PreparedStatement stmt,
          ResultSet rs) {
    if (rs != null) {
      try {
        rs.close();
      } catch (Exception ex) {
      }
    }

    if (stmt != null) {
      try {
        stmt.close();
      } catch (Exception ex) {
      }
    }

    if (conn != null) {
      try {
        conn.close();
      } catch (Exception ex) {
      }
    }
  }

  private static java.sql.Timestamp getCurrentTimeStamp() {

    java.util.Date today = new java.util.Date();
    return new java.sql.Timestamp(today.getTime());

  }

  private boolean isInExcludeList(String user, String[] excludedGroupList) {
    if (excludedGroupList == null || excludedGroupList.length == 0){
      return false;
    }
    String[] userGroups = findGroups(user);
    if (userGroups == null || userGroups.length == 0) {
      return false;
    }
    for (String twoFactorExclude : excludedGroupList) {
      for (String group : userGroups) {
        if (group.equals(twoFactorExclude)) {
          return true;
        }
      }

    }
    return false;
  }
}
