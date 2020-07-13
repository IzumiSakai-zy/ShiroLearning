# ShiroLearning
学习Shiro安全框架

## Shito

### Shiro与Spring security

* Shiro比Spring security更简单，更容易上手
* 在spring cloud微服务中为了统一技术栈为spring家族往往会选择spring security而不是shiro
****************
### 权限管理
* 定义：对用户访问系统的控制
* 包括：用户认证和用户授权
* 身份认证：判断一个用户是否为合法用户的过程
* 用户授权：即访问控制
************
### Shiro框架简介
* Apache一个强大且易用的java框架
* 执行身份验证、授权、密码学和会话管理
* 体系
  * Authentication认证——用户登录
  * Authorization授权——用户具有哪些权限
  * Session Management——会话管理
*******************
### Authentication认证
* 认证中的关键对象
  * Subjec 主体——访问系统的用户。可以是用户、程序等，所有进行认证的用户都被抽象成subject
  * Principle 身份信息—— 主体进行身份认证的标识，标志具有唯一性，比如账号、用户名
  * Credential 凭证信息—— 只有主体自己知道的安全信息，如密码、证书
* 认证流程
  *  第一步：主体的身份信息和凭证信息封装成一个令牌Token
  *  第二步：Security Managet验证Token是否合法
*******************
### 单机版用户认证
* 创建一个最简单的maven项目

* 导入依赖

  ```xml
  <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-spring</artifactId>
      <version>1.5.3</version>
  </dependency>
  ```
  
* 在resources目录下创建shiro.ini文件
  * 用来学习shiro时书写我们系统中的相关权限，后面不会使用
  ```ini
    [users]
    IzumiSakai=123456IS
    ZhangSan=123456ZS
    LiSi=123456LS
  ```
  
* 单机测试案例

  ```java
  public static void main(String[] args) {
      //创建安全管理器对象
      DefaultSecurityManager securityManager=new DefaultSecurityManager();
  
      //设置Realm(做认证时就读取这个Realm里面的数据)
      securityManager.setRealm(new IniRealm("classpath:shiro.ini"));
  
      //给全局的安全工具类设置使用的安全管理器
      SecurityUtils.setSecurityManager(securityManager);
  
      //关键对象, Subject主体
      Subject subject = SecurityUtils.getSubject();
  
      //创建令牌
      UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("IzumiSakai","123456");
  
      //执行登录。可以根据异常类型判断是身份信息还是凭证信息出错
      try {
          subject.login(usernamePasswordToken);
          System.out.println("认证成功");
          System.out.println("认证状态："+subject.isAuthenticated());
      }catch (UnknownAccountException e){
          System.out.println("用户名不存在");
          System.out.println("认证状态："+subject.isAuthenticated());
      }catch (IncorrectCredentialsException e){
          System.out.println("密码错误");
          System.out.println("认证状态："+subject.isAuthenticated());
      }
  }
  ```
**************
### 自定义Realm

* 前置知识：分析源码可以知道程序员可以自定义身份信息的比较，而凭证信息的比较是系统自动进行的

* 目的：将认证和授权的来源转为数据库

* ```java
  public class MyRealm extends AuthorizingRealm {
      //执行授权
      @Override
      protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
          return null;
      }
  	
      //执行认证
      @Override
      protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
          //获取用户名信息
          String principal = authenticationToken.getPrincipal().toString();
          //假装从数据库获取到用户信息进行比对
          if ("IzumiSakai".equals(principal)){
              //这样肯定不会报身份信息错误UnknownAccountException
              //参数一：返回数据库正确的用户名，参数二：返回数据库中正确的密码，参数三：提供当前的Realm名
              return new SimpleAuthenticationInfo("IzumiSakai","123456IS",this.getName());
          }else 
              return null;
      }
  }
  ```
  
* 测试：相比于上一个案例唯一不同是传给DefaultSecurityManager的Realm对象不同

********************

### MD5和Salt简介

* MD5作用：用于加密和签名(检验和)
* MD5特点
  * 相同内容无论做多少次运算结果相同， 可用于检查下载文件是否完全无差错
  * 不可逆。只能明生逆，不能逆生明
* 生成结果：16进制长度为32位的字符串
* 使用逻辑
  * 获取用户注册时输入的密码
  * 对该密码进行加salt，记录下salt的值
  * 在数据库中存放三个信息：用户名，含有salt的加密后的密码，salt的值
  * 用户登录时输入的密码
  * 密码拼接上对应的salt值，加密得到的密文和数据库相比较。

******************

### MD5+Salt实现

* MD5+salt使用示例

  ```java
  public static void main(String[] args) {
      //使用md5
      Md5Hash md5 = new Md5Hash("Izumi Sakai");
      System.out.println("md5:"+md5.toHex());
  
      //使用md5+salt
      Md5Hash md5Salt = new Md5Hash("Izumi Sakai","KT*}d`");
      System.out.println("md5+salt:"+md5Salt.toHex());
  
      //使用md5+salt+hash散列
      Md5Hash md5SaltHash = new Md5Hash("Izumi Sakai","KT*}d`",1024);//1024是散列次数
      System.out.println("md5+salt+hash散列:"+md5SaltHash.toHex());
  }
  ```
  
* MyMd5Realm的`protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)`方法代码
  
  * 核心是`SimpleAuthenticationInfo`的四个参数，其中第三个参数salt的格式固定，只能这样写
  
  ```java
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
      String principal = authenticationToken.getPrincipal().toString();
      if ("Izumi Sakai".equals(principal)){
          return new SimpleAuthenticationInfo(
                  "Izumi Sakai",
                  "95cd23ec32d9b359c71cd487b0fcf8d8",
                  ByteSource.Util.bytes("xyz"),//加入的salt
                  this.getName());
      }else
          return null;
  }
  ```
  
* 使用MyMd5Realm进行登录的实例代码部分
  
  * 重点就是设置新的CredentialsMatcher而不使用默认的CredentialsMatcher
  * 其他前后代码和上面案例一样
  
  ```java
  //创建自定义的Realm
  MyMd5Realm myMd5Realm=new MyMd5Realm();
  //创建非默认的CredentialsMatcher
  HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
  //设置算法的名字
  hashedCredentialsMatcher.setHashAlgorithmName("md5");
  //设置hash散列的次数为1024
  hashedCredentialsMatcher.setHashIterations(1024);
  //调用set方法设置非默认的CredentialsMatcher
  myMd5Realm.setCredentialsMatcher(hashedCredentialsMatcher);
  //把设置后的Realm放入安全管理器
  defaultWebSecurityManager.setRealm(myMd5Realm)
  ```
*********************
### 用户授权简介

* 授权：对通过认证的主体分配系统资源使用权限
* 关键对象
  * Subject——主体
  * Resource——资源，分为资源类型和资源实例
  * Permission——权限，权限必须依赖于资源
* 授权方式
  * 基于角色的访问控制(Role-Based-Acess-Control)
  * 基于资源的访问控制(Resource-Based-Acess-Control)
* 权限字符串
  * 格式"资源标志符 : 操作 : 资源实例标志符"

****************

Shiro中的授权实现

* 基于角色的Realm中`protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection)`方法的代码

  ```java
  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
      //获取首用户名
      String primaryPrincipal = principalCollection.getPrimaryPrincipal().toString();
  
      //根据身份信息、用户名、获取当前用户的角色信息和权限信息
      SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();
  
      //根据数据库查询的角色信息进行角色分配
      authorizationInfo.addRoles(Arrays.asList("admin","user"));
  
      return authorizationInfo;
  }
  ```
  
* 基于角色登录中的示例

  ```java
  //基于角色的访问控制
  if (subject.isAuthenticated()){
      System.out.println("管理员权限"+subject.hasRole("admin"));
      System.out.println("双权限"+subject.hasAllRoles(Arrays.asList("user","admin")));
  }
  ```
  
* 基于资源的Realm中`protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection)`方法的代码

  ```java
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
      //获取首用户名
      String primaryPrincipal = principalCollection.getPrimaryPrincipal().toString();
  
      //根据身份信息、用户名、获取当前用户的角色信息和权限信息
      SimpleAuthorizationInfo authorizationInfo=new SimpleAuthorizationInfo();
  
      //根据数据库查询的角色信息进行角权限分配
      authorizationInfo.addStringPermissions(Arrays.asList("user:*:*","common:create:01"));
  
      return authorizationInfo;
  }
  ```

* 基于资源登录中的示例

  ```java
  //基于资源的访问控制
  if (subject.isAuthenticated()){
      System.out.println("对user模块的01资源是否拥有所有权限"+subject.isPermitted("user:*:01"));
  }
  ```

******************

### Shiro与Springboot整合案例

* 导入Shiro和其他相关依赖

  ```xml
  <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-spring</artifactId>
      <version>1.5.3</version>
  </dependency>
  <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-ehcache</artifactId>
      <version>1.5.3</version>
  </dependency>
  ```
  
* 额外：整合Druid连接池

  ```yaml
  spring:
    datasource:
      username: root
      password: 542270191MSzyl
      url: jdbc:mysql://localhost:3306/shiro-springboot?useUnicode=true&characterEncoding=utf8
      type: com.alibaba.druid.pool.DruidDataSource
      druid:
        initial-size: 5
        min-idle: 5
        max-active: 20
        max-wait: 40000
        time-between-eviction-runs-millis: 60000
        min-evictable-idle-time-millis: 30000
        validation-query: selcet 1 from dual
        test-while-idle: true
        test-on-borrow: false
        test-on-return: false
        pool-prepared-statements: true
  mybatis:
    mapper-locations: classpath:mybatis/*.xml
    
  #  <dependency>
  #        <groupId>org.mybatis.spring.boot</groupId>
  #        <artifactId>mybatis-spring-boot-starter</artifactId>
  #         <version>2.1.3</version>
  #  </dependency>
  
  ```
  
* Shiro内置过滤关键词
  * anno:无需认证
  * authc：必须认证
  * user:拥有 记住我 能访问
  * perms：拥有对某个资源的权限才能访问
  * role：拥有某个角色权限才能访问

* Shiro的配置类，主要功能是把关键类放入spring容器

  ```java
  @Configuration
  public class ShiroConfig {
      //过滤器，绑定安全管理器
      @Bean
      public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("defaultWebSecurityManager") DefaultWebSecurityManager defaultWebSecurityManager){
          //创建新的过滤器
          ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
          //绑定安全管理器
          shiroFilterFactoryBean.setSecurityManager(defaultWebSecurityManager);
          //创建链式hashMap
          Map<String, String> filterChainDefinitionMap=new LinkedHashMap<>();
          //往hash链中填键值对设置过滤。其中键的值是url中的访问路径，值是固定的几个
          filterChainDefinitionMap.put("/user/*","authc");//指user路径下的所有访问
          filterChainDefinitionMap.put("/add","authc");
          filterChainDefinitionMap.put("/update","authc");
          //授权设置
          filterChainDefinitionMap.put("/add","perms[/:add:*]");
          //设置过滤器的过滤列表
          shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
          //设置默认跳转的登录URL地址
          shiroFilterFactoryBean.setLoginUrl("/toLogin");
          //设置未授权URL地址
          shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized");
          return shiroFilterFactoryBean;
      }
  
      //安全管理器，绑定Realm
      @Bean(name = "defaultWebSecurityManager")
      public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm){
          DefaultWebSecurityManager securityManager=new DefaultWebSecurityManager();
          securityManager.setRealm(userRealm);
          return securityManager;
      }
  
      //把UserRealm放入容器，默认名字为方法名，可通过name属性修改
      @Bean(name = "userRealm")
      UserRealm getUserRealm(){
          //创建自定义的Realm
          UserRealm userRealm = new UserRealm();
          //创建hash凭证匹配器
          HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
          //设置这个匹配器的参数
          hashedCredentialsMatcher.setHashAlgorithmName("md5");
          hashedCredentialsMatcher.setHashIterations(1024);
          //更改Realm的默认匹配器为新创建且设置还参数的hash匹配器
          userRealm.setCredentialsMatcher(hashedCredentialsMatcher);
          return userRealm;
      }
  
      //因为没有spring的配置文件，自己手动放入shiro与thymeleaf的类
      @Bean
      public ShiroDialect getShiroDialect(){
          return new ShiroDialect();
      }
  }
  ```

* UserController类代码

  ```java
  @Controller
  public class UserController {
      @Autowired
      private UserMapper userMapper;
  
      @RequestMapping("/toLogin")
      public String login(){
          return "login";
      }
      @RequestMapping("/login")
      public String toLogin(String username, String password, Model model){
          //获取主体的方法永远都是这个
          Subject subject = SecurityUtils.getSubject();
          //创建一个令牌token，传入表单的账号和密码
          UsernamePasswordToken token = new UsernamePasswordToken(username, password);
          //尝试登陆并捕获错误
          try{
              subject.login(token);
              return "index";
          }catch (UnknownAccountException e){
              model.addAttribute("error","用户名不存在");
              return "forward:toLogin";
          }catch (IncorrectCredentialsException e){
              model.addAttribute("error","密码错误");
              return "forward:toLogin";
          }catch (LockedAccountException e){
              model.addAttribute("error","此账户已被锁定，请联系管理员");
              return "forward:toLogin";
          }
      }
  
      @RequestMapping("/register")
      public String toRegister(HttpServletRequest request){
          //从HttpServletRequest获取参数，其实可以直接获取
          String username = request.getParameter("username");
          String password = request.getParameter("password");
          //设置盐值
          String salt=String.valueOf(Math.round(Math.random()*10000));
          //设置加密后的密码
          String hexPassword = new Md5Hash(password, salt, 1024).toHex();
          //把新注册的用户insert到数据库
          User user=new User();
          user.setUserName(username);
          user.setPassword(hexPassword);
          user.setSalt(salt);
          userMapper.insert(user);
          return "login";
      }
  
      @RequestMapping("/toRegister")
      public String register(){
          return "register";
      }
  
      @RequestMapping("/unauthorized")
      public String unauthorized(){
          return "unauthorized";
      }
  }
  ```
  
* Realm代码

  ```java
  public class UserRealm extends AuthorizingRealm {
      //数据库层接口
      @Autowired
      private UserMapper userMapper;
      
      @Override
      protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
          //获取首用户名，来源是下面方法的第一个参数
          String principal = principalCollection.getPrimaryPrincipal().toString();
          //创建要返回的授权信息
          SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
          //根据查询数据库添加权限。此处是设置只有Izumi Sakai有权限
          if ("Izumi Sakai".equals(principal))
              authorizationInfo.addStringPermission("/:add:*");//对"/"URL路径下所有实体具有add权限。也就是有"/"
          return authorizationInfo;
      }
  
      @Override
      protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
          String principal = authenticationToken.getPrincipal().toString();
          User user = userMapper.findByUserName(principal);
          if (user==null)
              return null;
          //第一个参数很关键，它是上面的授权能够获取到的值
          SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
                  user.getUserName(),
                  user.getPassword(),
                  ByteSource.Util.bytes(user.getSalt()),
                  this.getName());
          return simpleAuthenticationInfo;
      }
  }
  ```
  
* 注意事项

  * springboot的测试尽量不要在test根目录下测试，有可能不会编译根本没有springboot环境。如果需要测试，也必须加上`@SpringbootTest`注解
  * 授权`/user/:add:*`表示对"/user/"下所有URL路径的所有实体都有add权限。也就是说授权控制是基于URL路径的，路径的设置很重要。
  * "toLogin"指到登录页面，"login"指处理登录表单

******************

### Shiro与thymeleaf整合

* 添加依赖

  ```xml
  <dependency>
      <groupId>com.github.theborakompanioni</groupId>
      <artifactId>thymeleaf-extras-shiro</artifactId>
      <version>2.0.0</version>
  </dependency>
  ```
  
* 添加关键类进容器

  ```java
  @Bean
  public ShiroDialect getShiroDialect(){
      return new ShiroDialect();
  }
  ```
  
* 前端实现

  * 首先要导入`xmlns:shiro="http://www.thymeleaf.org/thymeleaf-extras-shiro`命名空间
  * 然后在标签中使用`shiro:hasPermission="/:add"`

  ```HTML
  <!DOCTYPE html>
  <html lang="en" xmlns:th="http://www.thymeleaf.org" xmlns:shiro="http://www.thymeleaf.org/thymeleaf-extras-shiro">
  <head>
      <meta charset="UTF-8">
      <title>首页</title>
  </head>
  <body>
      <h1>首页</h1>
      <div th:text="${msg}"></div>
      <!--实现拦截，没有权限根本不显示-->
      <a th:href="@{/add}" shiro:hasPermission="/:add">add</a>
      <a th:href="@{/update}" shiro:hasPermission="/:update">update</a>
  </body>
  </html>
  ```

********************************

## Sping Secuity

******************

### 基础概念

* 会话机制：会话系统就是为了保持当前用户登录状态所提供的机制，有session和token两种常用机制
  * token会话机制：首次认证通过后服务端发送给客户端一个令牌token，下次再请求时就携带token再次发送请求
  * session和token两者之间的区别：
    * session：服务端需要存储session信息，客户端要支持cookie
    * token：服务端不需要存储信息，并且不限制存储方式

******************

### 用户认证授权

* 导入依赖

  ```XML
  <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
  </dependency>
  ```

* 核心类和注解、

  * `WebSecurityConfigurationAdapter`——自定义security策略
  * ``

* 链式编程实现

  * 首先继承`WebSecurityConfigurerAdapter`类，并注解开启
  * `protected void configure(HttpSecurity http)`这个方法是控制授权
    * 可以按照角色资源授权，使用链式编程
    * 无权限可以跳转到登录页面
      * loginPage("/toLogin")是登录的HTML页面
      * loginProcessingUrl("/login")是处理登录表单的action地址
    * 可以实现注销功能
    * 可以开启remember me
  * 认证可以从密码认证，也可以从JDBC数据库认证，但密码必须加密，否则会出错

  ```java
  @EnableWebSecurity
  public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
      //授权
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          //按照角色授权
          http.authorizeRequests()
                  .antMatchers("/","/index.html").permitAll()
                  .antMatchers("/level1/**").hasRole("vip1")
                  .antMatchers("/level2/**").hasRole("vip2")
                  .antMatchers("/level3/**").hasRole("vip3");
          //默认跳到登录页面
          http.formLogin()
                  .loginPage("/toLogin")
                  .loginProcessingUrl("/login")
                  .defaultSuccessUrl("/")
                  .permitAll();
          //注销
          http.logout()
                  .logoutUrl("/toLogout")
                  .logoutSuccessUrl("/").permitAll();
          //开启记住我功能。本质就是加了一个cookie
          http.rememberMe().rememberMeParameter("remember");
      }
  
      //认证
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          //从内存认证
          auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                  .withUser("Izumi Sakai").password(new BCryptPasswordEncoder().encode("123456IS")).roles("vip1","vip2")
                  .and()
                  .withUser("Zhang San").password(new BCryptPasswordEncoder().encode("123456ZS")).roles("vip3");
          //从jdbc数据库认证
          //auth.jdbcAuthentication();
      }
  }
  ```

