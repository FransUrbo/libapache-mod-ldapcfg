/*
  mod_ldap_cfg



*/


// General #includes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// LDAP #includes

#include <ldap.h>
#include <sasl/sasl.h>

// Apache #includes

#include <httpd.h>
#include <http_config.h>


////
//
// Constants
//
////

// Error Codes

#define LDAP_CFG_OK             0
#define LDAP_CFG_ERROR          1

// Constance, but not prudence

#define LDAP_CFG_SECTION_OBJ    "ApacheSectionObj"
#define LDAP_CFG_SECTION_NAME   "ApacheSectionName"
#define LDAP_CFG_SECTION_ARG    "ApacheSectionArg";

#define LDAP_CFG_PREFIX         "Apache"
#define LDAP_CFG_PREFIX_LENGTH  6
#define LDAP_CFG_TAB_LENGTH     4

// Just like they taught me in CSC 210

#define LDAP_CFG_FSM_INIT       1
#define LDAP_CFG_FSM_VAR        2
#define LDAP_CFG_FSM_NUM        3


// #define Debugging Routines

#define ERROR( ... )         fprintf( stderr, __VA_ARGS__ )
#define LDEBUG( level, ... ) if( ldap_cfg_debug_level & ( level ) ) fprintf( stderr, __VA_ARGS__ );

// Debug Levels

#define LDAP_CFG_DEBUG_NONE         0
#define LDAP_CFG_DEBUG_CFG          1
#define LDAP_CFG_DEBUG_LINE         2
#define LDAP_CFG_DEBUG_SRCH         4
#define LDAP_CFG_DEBUG_CNXN         8
#define LDAP_CFG_DEBUG_SASL         16
#define LDAP_CFG_DEBUG_CMD          32
#define LDAP_CFG_DEBUG_FUNC         64
#define LDAP_CFG_DEBUG_TODO         128
#define LDAP_CFG_DEBUG_ALL         -1


// Let Apache know that we are here and we mean business

module MODULE_VAR_EXPORT ldap_cfg_module;




////
//
// Data-structure definitions
//
////


/*
  ldap_cfg_srv_cfg is used to hold all the configuration information
  specified by "LDAPCfg_*" directives, specifying information about who
  we are connecting to and how for our LDAP session
*/
typedef struct
{
     char * bind_dn;
     char * password;
     char * host;
     int    port;
     char * uri;
     int    version;
     char * sasl_authc;
     char * sasl_authz;
     char * sasl_realm;
     char * sasl_props;
     char * sasl_mech;
     int    simple_bind;
     int    kerberos_auth;
     int    kerberos_onestep_auth;
     int    use_tls;
     int    follow_referrals;
     
     char * base_dn;
     int    scope;

}
ldap_cfg_srv_cfg;



/*
  ldap_cfg_recursive_args is used to hold a number of useful objects
  and arguments.  Our call stack can be pretty deep and having to pass
  all the various pieces of data down to that last stack is much
  easier when it is all bundled up in one structure.
 */
typedef struct
{
     pool *         mem_pool;
     LDAP *         ldap_rec;

     char **        attr_list;
     array_header * attr_ah;
     
     int            scope;
     void *         call_back;
     void *         call_back_data;

     // Apache Config Data
     cmd_parms      * parms;
     void           * config;
}
ldap_cfg_parms;



/*
  ldap_cfg_dn_entry_struct is used to hold a single LDAPMessage record
  as well as it's exploded DN and the number of DN components.
  Additionally, it has fields for creating a linked list of entries,
  for use in <Section> management.
*/
struct ldap_cfg_dn_entry_struct
{
     char ** ex_dn;
     int dn_count;
     LDAPMessage * msg;
     struct ldap_cfg_dn_entry_struct * prev;
     char * section_name;

};

typedef struct ldap_cfg_dn_entry_struct ldap_cfg_dn_entry;

/*
  ldap_cfg_word_array is used when a search string is broken into
  tokens when looking for variable substitution directives.
 */  
typedef struct
{
     array_header * tokens_ah;
     int          * positions;
}
ldap_cfg_word_array;




/*
  ldap_cfg_config_stack is used to create a virtual config file by
  holding a list of all configuration directives be sent to Apache.
  These directives will the be read of by ap_srm_command_loop()
*/
typedef struct
{
     // This array will contain (char *) of all the configuration
     // directives we pull from LDAP and will pass to Apache to load
     array_header * config_ah;
     int index;

     // <Section> stack management
     ldap_cfg_dn_entry * section_stack;
     int                 section_depth;
}
ldap_cfg_config_stack;







// Global Data structure

int                 ldap_cfg_debug_level = 0;

// The following variables are used to the "LDAPCfg_Search" result
// stack
pool              * ldap_cfg_attr_stack_pool = NULL;
array_header      * ldap_cfg_attr_stack_ah = NULL;





////
//
// Function Declarations
//
////

// LDAP Session

const char * ldap_cfg_search_session (
     cmd_parms * parms,
     void * config,
     void * call_back,
     const char * filter,
     const char * attr_name );


// Connection routines

static LDAP * ldap_cfg_connect (
     ldap_cfg_srv_cfg * cfg );

static LDAP * ldap_cfg_connect_init (
     ldap_cfg_srv_cfg * cfg );

static int ldap_cfg_connect_bind (
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec );

static int ldap_cfg_ldap_bind_s (
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec,
     int auth_method );

static int ldap_cfg_connect_bind_v2 (
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec );

static int ldap_cfg_connect_bind_v3 (
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec );


// SASL-specific connection routines

int ldap_cfg_sasl_interact (
     LDAP * ldap_rec,
     unsigned flags,
     void * data,
     void * in );

static int ldap_cfg_sasl_interaction (
     LDAP * ldap_rec,
     unsigned flags,
     sasl_interact_t *interact,
     ldap_cfg_srv_cfg * cfg );


// Attribute Stack management and Variable Substitution

int  ldap_cfg_parse_string_for_vars (
     pool * p,
     array_header * ah,
     ldap_cfg_word_array * parts,
     const char * to_parse );

void ldap_cfg_extract_word_token (
     pool * p,
     array_header * ah,
     const char * source, int length );

void ldap_cfg_attr_stack_add_values (
     array_header * ah,
     char ** values );

void ldap_cfg_attr_stack_add_attr (
     array_header * attr_stack,
     array_header * value_stack );

int ldap_cfg_recursive_var_subst (
     ldap_cfg_parms * args,
     ldap_cfg_word_array * base,
     ldap_cfg_word_array * filter,
     int var_num );

void ldap_cfg_single_var_subst (
     int pos_set,
     char ** tokens,
     char * elt );


// LDAP Search Routines

int ldap_cfg_perform_search (
     ldap_cfg_parms * args,
     ldap_cfg_word_array * base,
     ldap_cfg_word_array * filter );

int ldap_cfg_sort_entries (
     pool * p,
     LDAP * ld,
     LDAPMessage * msg,
     ldap_cfg_dn_entry ** entries_ptr );

int ldap_cfg_reverse_dn_cmp (
     const void * a,
     const void *b);


// Result processing call-backs

int ldap_cfg_cb_search (
     ldap_cfg_parms * args,
     LDAPMessage * res );

int ldap_cfg_cb_load (
     ldap_cfg_parms * args,
     LDAPMessage * res );


// Configuration processing

int ldap_cfg_handle_config_obj (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry );

int ldap_cfg_hanlde_section_obj (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry );

int ldap_cfg_handle_plain_obj (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry,
     int section_check );

int ldap_cfg_handle_comand (
     ldap_cfg_parms * args,
     const char * config_string );

int ldap_cfg_apache_command_loop (
     ldap_cfg_parms * args );


static void * ldap_cfg_ah_getstr (
     void * buf,
     size_t bufsiz,
     void * param );

// Configuration processing support routines

int ldap_cfg_is_section_obj (
     LDAP * ld,
     LDAPMessage * entry );

int ldap_cfg_check_section_stack (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry );

int ldap_cfg_is_sub_dn (
     ldap_cfg_dn_entry * parent,
     ldap_cfg_dn_entry * child );

int ldap_cfg_is_apache_dir (
     const char * dir );

int ldap_cfg_is_raw_arg (
     const char * dir );

int ldap_cfg_is_section_attr (
     const char * dir );

void ldap_cfg_underscore_convert (
     char * to_convert );


// Utility Functions

char * ldap_cfg_array_pstrcat (
     pool * p,
     array_header * ah );

void ldap_cfg_print_offset (
     int depth,
     int debug_level );


////
//
// Apache 'LDAPCfg_*' Command processing routines
//
////

     
static void * ldap_cfg_create_srv_config(
     pool * p,
     server_rec * s)  
{ 
     ldap_cfg_srv_cfg * scfg =
          (ldap_cfg_srv_cfg *) ap_pcalloc( p, sizeof( *scfg ) );

     /* Prep scfg entry */
     LDEBUG( LDAP_CFG_DEBUG_TODO, "Creating new Server Config object\n" );
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_create_srv_config()\n" );

     // Default to Version 3
     scfg->version = LDAP_VERSION3;
     scfg->scope = LDAP_SCOPE_SUBTREE;
     scfg->follow_referrals = 0;
     scfg->use_tls = 0;

     if( ldap_cfg_attr_stack_pool == NULL )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO,
                  "Creating attribute-stack memory pool\n" );
          ldap_cfg_attr_stack_pool = ap_make_sub_pool( p );

          LDEBUG( LDAP_CFG_DEBUG_TODO, "Creating attribute-stack\n" );
          ldap_cfg_attr_stack_ah =
               ap_make_array( ldap_cfg_attr_stack_pool,
                              4,
                              sizeof( array_header * ) );
     }

     return (void *) scfg;
}

static void * ldap_cfg_merge_srv_config(
     pool *p,
     void *base,
     void *new )
{ 
     //ldap_cfg_srv_cfg * scfg =
     //     (ldap_cfg_srv_cfg *) ap_pcalloc( p, sizeof( *scfg ) );

     LDEBUG( LDAP_CFG_DEBUG_TODO, "Merging Server Config objects\n" );
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_merge_srv_config()\n" );
     
     // TODO: Merge server objects
     // return (void *) scfg;

     return base;

}




static ldap_cfg_srv_cfg * ldap_cfg_get_srv_cfg( cmd_parms * cmd )
{
     server_rec * s = cmd->server;

     return (ldap_cfg_srv_cfg *)
          ap_get_module_config( 
               s->module_config,
               &ldap_cfg_module);
}
     



static const char *ldap_cfg_binddn_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->bind_dn = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_binddn_cmd( bind_dn => \"%s\" )\n",
             cfg->bind_dn );

     return NULL;
}

static const char *ldap_cfg_password_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->password = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_password_cmd( password => \"%s\" )\n",
             cfg->password );

     return NULL;
}

static const char *ldap_cfg_host_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg,
     const char * port )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->host = ap_pstrdup( cmd->temp_pool, arg );

     // Port is optional
     if( port != NULL )
     {
          cfg->port = atoi( port );
     }

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_host_cmd( host =>  \"%s\", port => \"%s\" (%d) )\n",
             arg,
             port,
             cfg->port );

     return NULL;
}

static const char * ldap_cfg_uri_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->uri = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_uri_cmd( URI => \"%s\" )\n",
             cfg->uri );

     return NULL;
}

static const char * ldap_cfg_version_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->version = atoi( arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_version_cmd( version => \"%s\" (%d) )\n",
             arg,
             cfg->version );

     return NULL;
}

static const char * ldap_cfg_sasl_authc_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->sasl_authc = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( ( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC ),
             "ldap_cfg_sasl_authc_cmd( AuthenticationID => \"%s\" )\n",
             arg );

     return NULL;
}

static const char * ldap_cfg_sasl_authz_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->sasl_authz = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_sasl_authz_cmd( AuthorizationID => \"%s\" )\n",
             arg );

     return NULL;
}

static const char * ldap_cfg_sasl_realm_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->sasl_realm = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_sasl_realm_cmd( realm => \"%s\" )\n",
             arg );

     return NULL;
}

static const char * ldap_cfg_sasl_mech_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->sasl_mech = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_sasl_mech_cmd( mechanism => \"%s\" )\n",
             arg );
     return NULL;
}

static const char * ldap_cfg_sasl_props_cmd (
     cmd_parms *cmd,
     void *mconfig,
     const char *arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->sasl_props = ap_pstrdup( cmd->temp_pool, arg );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_sasl_props_cmd( props => \"%s\" )\n",
             arg );

     return NULL;
}

static const char * ldap_cfg_simple_bind_cmd (
     cmd_parms *cmd,
     void *mconfig )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->simple_bind = 1; 

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_simple_bind_cmd()\n" );
     return NULL;
}

static const char * ldap_cfg_kerberos_bind_cmd(
     cmd_parms *cmd,
     void *mconfig )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->kerberos_auth = 1; 

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_kerberos_bind_cmd()\n" );

     return NULL;
}

static const char * ldap_cfg_kerberos_onestep_bind_cmd (
     cmd_parms *cmd,
     void *mconfig )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->kerberos_onestep_auth = 1; 

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_kerberos_onestep_bind_cmd()\n" );

     return NULL;
}

static const char * ldap_cfg_tls_cmd (
     cmd_parms *cmd,
     void *mconfig )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );
     cfg->use_tls = 1; 

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_tls_cmd()\n" );

     return NULL;
}

static const char * ldap_cfg_search_scope_cmd (
     cmd_parms * cmd,
     void * mconfig,
     const char * arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_search_scope_cmd( scope => \"%s\" )\n",
             arg );

     if( strcasecmp( arg, "base" ) == 0 )
     {
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "Search scope set to LDAP_SCOPE_BASE\n" );
          cfg->scope = LDAP_SCOPE_BASE;
     }
     else if( strcasecmp( arg, "sub" ) == 0 )
     {
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "Search scope set to LDAP_SCOPE_SUBTREE\n" );
          cfg->scope = LDAP_SCOPE_SUBTREE;
     }
     else if( strcasecmp( arg, "one" ) == 0 )
     {
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "Search scope set to LDAP_SCOPE_ONELEVEL\n" );
          cfg->scope = LDAP_SCOPE_ONELEVEL;
     }
     else
     {
          LDEBUG( LDAP_CFG_DEBUG_CMD,
                  "Invalid search scope: %s\n", arg );
          return "Scope can only be 'sub', 'base', or 'one'";
     }
     
     return NULL;
}

static const char * ldap_cfg_base_dn_cmd (
     cmd_parms * cmd,
     void * mconfig,
     const char * arg )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_base_dn_cmd( base => \"%s\" )\n",
             arg );

     if( strcmp( arg, "-" ) == 0 )
     {
          LDEBUG( LDAP_CFG_DEBUG_CMD, "Clearing base search DN\n" );
          cfg->base_dn = NULL;
     }
     else
     {
          cfg->base_dn = ap_pstrdup( cmd->temp_pool, arg );
     }

     return NULL;
}

static const char * ldap_cfg_search_cmd (
     cmd_parms *cmd,
     void * mconfig,
     const char * filter,
     const char * attr )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC, 
             "ldap_cfg_search_cmd( filter => \"%s\", attr => \"%s\" )\n",
             filter,
             attr );

     return ldap_cfg_search_session(
          cmd,
          mconfig,
          ldap_cfg_cb_search,
          filter,
          attr );
}

static const char *ldap_cfg_load_cmd (
     cmd_parms *cmd,
     void * mconfig,
     const char *filter )
{
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( cmd );

     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_load_cmd( filter => \"%s\" )\n",
             filter );

     return ldap_cfg_search_session(
          cmd,
          mconfig,
          ldap_cfg_cb_load,
          filter,
          NULL );
}

static const char *ldap_cfg_debug_cmd (
     cmd_parms * cmd,
     void * mconfig,
     const char * level )
{
     ldap_cfg_debug_level = atoi( level );
     LDEBUG( LDAP_CFG_DEBUG_CMD | LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_debug_cmd( level => \"%s\" (%d) )\n",
             level,
             ldap_cfg_debug_level );

     return NULL;
}






//////
//
// LDAP Session
//
//////

const char * ldap_cfg_search_session(
     cmd_parms * parms,
     void * config,
     void * call_back,
     const char * filter,
     const char * attr_name )
{
     char * attr_list[2];
     int error = 0;
     ldap_cfg_srv_cfg * cfg = ldap_cfg_get_srv_cfg( parms );
     
     ldap_cfg_word_array filter_list, base_list;
     ldap_cfg_parms args;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_search_session()\n" );

     // Prepare argument structure
     args.parms = parms;
     args.config = config;
     args.attr_list = NULL;
     args.attr_ah = ldap_cfg_attr_stack_ah;
     args.scope = cfg->scope;
     args.call_back = call_back;
     args.call_back_data = NULL;

     // Make a sub-pool for all Session-specific memory operations
     args.mem_pool = ap_make_sub_pool( args.parms->temp_pool );
     
     // Connect to LDAP server
     args.ldap_rec = ldap_cfg_connect( cfg );

     if( args.ldap_rec == NULL )
     {
          ERROR( "Error connecting to LDAP database\n" );
          return "Error connecting to LDAP database";
     }

     // Prep attr list - a (char *) array with last entry set to NULL
     if( attr_name != NULL )
     {
          attr_list[0] = (char *) attr_name;
          attr_list[1] = NULL;
          args.attr_list = attr_list;
     }

     // Parse base_dn and filter for variables to be substitued
     if( ldap_cfg_parse_string_for_vars( args.mem_pool,
                                         args.attr_ah,
                                         & base_list,
                                         cfg->base_dn ) == LDAP_CFG_OK
         &&
         ldap_cfg_parse_string_for_vars( args.mem_pool,
                                         args.attr_ah,
                                         & filter_list,
                                         filter )       == LDAP_CFG_OK )
     {
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "Pre-substituted search: Base => \"%s\", Filter => \"%s\", N => %d\n",
                  cfg->base_dn,
                  filter,
                  ldap_cfg_attr_stack_ah->nelts ); 

          if( ldap_cfg_recursive_var_subst(
                   & args,
                   & base_list,
                   & filter_list,
                   ldap_cfg_attr_stack_ah->nelts
                   ) != LDAP_CFG_OK )
          {
               error = 1;
          }

          // When all is said and done, we call the call_back once
          // more with a NULL result set to let it do search cleanup
          if( error != 1 )
          {
               error = ( ( int (*) ( ldap_cfg_parms *, LDAPMessage * ) )
                         args.call_back )( &args, NULL );          
          }


     }
     else
     {
          error = 1;
     }

     // Unbind when everything is complete
     LDEBUG( LDAP_CFG_DEBUG_CNXN, "Unbinding LDAP connection\n" );
     ldap_unbind( args.ldap_rec );

     // Destory temporary memory pool
     ap_destroy_pool( args.mem_pool );

     if( error ) 
     {
          return "An error occured with mod_ldap_cfg";
     }
     
     return NULL;
}






////
//
//  Connection Routines
//
//
////


/*
  ldap_cfg_connect()

  Prepares an inital LDAP record and binds to it using the parameters
  specified in the ldap_cfg_srv_cfg object.
*/  
static LDAP * ldap_cfg_connect(
     ldap_cfg_srv_cfg * cfg )
{
     LDAP * ldap_rec;
     
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_connect()\n" );

     ldap_rec = ldap_cfg_connect_init( cfg );
     
     if( ldap_rec == NULL )
     {
          ERROR( "ldap_init failed!\n" );
          return NULL;
     }
     
     if( ldap_cfg_connect_bind( cfg, ldap_rec ) != LDAP_CFG_OK )
     {
          ERROR( "LDAP Connect failed.\n" );
          return NULL;
     }

     return ldap_rec;
}




/*
  ldap_cfg_connect_init()

  Prepares a host/port combo from the cfg object and calls
  the ldap_init function to create the initial LDAP object.
*/
static LDAP * ldap_cfg_connect_init(
     ldap_cfg_srv_cfg * cfg )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_connect_init()\n" );

     if( cfg->host != NULL && cfg->uri != NULL )
     {
          ERROR( "You can't specify both a hostname AND a URI!\n" );
          return NULL;
     }

     if( cfg->uri != NULL )
     {
          LDAP ** ldap_rec_ptr;
          int rc;

          LDEBUG( LDAP_CFG_DEBUG_CNXN,
                  "ldap_initialize( uri => \"%s\" )\n",
                  cfg->uri );

          rc = ldap_initialize( ldap_rec_ptr, cfg->uri );
          if( rc != LDAP_SUCCESS )
          {
               ERROR( "Could not create LDAP session handle (%d): %s\n",
                      rc, ldap_err2string(rc) );
               return NULL;
          }
          return *ldap_rec_ptr;
     }
     else
     {
          char * host_name = "localhost";
          int port = LDAP_PORT;

          if( cfg->host != NULL ) host_name = cfg->host;
          if( cfg->port != 0 ) port = cfg->port;

          LDEBUG( LDAP_CFG_DEBUG_CNXN,
                  "ldap_init( %s, %d )\n",
                  host_name, port );
          
          return ldap_init( host_name, port );
     }
}




/*
  ldap_cfg_connect_bind()
  
  Based on parameters from the cfg object, sets the LDAP Protocol
  Version and then calls the bind routine specific to that protocol version.

*/
static int ldap_cfg_connect_bind(
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_connect_bind()\n" );
     LDEBUG( LDAP_CFG_DEBUG_TODO,
             "ldap_set_option( ldap_rec, LDAP_OPT_PROTOCOL_VERSION, %d )\n",
             cfg->version );

     if( ldap_set_option( ldap_rec, LDAP_OPT_PROTOCOL_VERSION, &cfg->version )
         != LDAP_OPT_SUCCESS )
     {
          ERROR( "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", cfg->version );
          return LDAP_CFG_ERROR;
     }

     LDEBUG( LDAP_CFG_DEBUG_TODO,
             "ldap_set_option( LDAP_OPT_REFERRALS, follow => %d )\n",
	     cfg->follow_referrals );
     if( ldap_set_option( ldap_rec,
                          LDAP_OPT_REFERRALS,
                          cfg->follow_referrals ?
			  LDAP_OPT_ON :
			  LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
          
     {
          ERROR( "Could not set LDAP_OPT_REFERRALS\n" );
          return LDAP_CFG_ERROR;
     }

     switch( cfg->version )
     {
     case LDAP_VERSION2:

          return ldap_cfg_connect_bind_v2( cfg, ldap_rec );
          break;

     case LDAP_VERSION3:
          
          return ldap_cfg_connect_bind_v3( cfg, ldap_rec );
          break;

     default:

          ERROR( "Invalid LDAP Protocol Version Specified: %d\n",
                 cfg->version );

          return LDAP_CFG_ERROR;
          break;
     }
}



/*
  ldap_cfg_ldap_bind_s()

  Performs a simple LDAP bind
*/
static int ldap_cfg_ldap_bind_s(
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec,
     int auth_method )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_ldap_bind_s()\n" );
     LDEBUG( LDAP_CFG_DEBUG_CNXN,
             "ldap_bind_s( bind_dn => \"%s\", password => \"%s\" )\n",
             cfg->bind_dn, cfg->password );

     if( ldap_bind_s( ldap_rec,
                      cfg->bind_dn,
                      cfg->password, 
                      auth_method )
         != LDAP_SUCCESS )
     {
          ldap_perror( ldap_rec, "Simple Bind Failure" );
          return LDAP_CFG_ERROR;
     }

     LDEBUG( LDAP_CFG_DEBUG_CNXN, "ldap_bind_s successful\n" );
     return LDAP_CFG_OK;
}




/*
  ldap_cfg_connect_bind_v2()

  Version 2 of the LDAP protocol supports the following bind methods:

  Can:    Simple and Kerberos*
  Cannot: Manage DSA IT, SASL,and TLS
*/
static int ldap_cfg_connect_bind_v2(
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec )
{
     // We default to Simple Authentication for V2
     int auth_method = LDAP_AUTH_SIMPLE;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_connect_bind_v2()\n" );
     LDEBUG( LDAP_CFG_DEBUG_CNXN, "Default Auth Method (v2) = Simple\n" );

     if( cfg->simple_bind ^ cfg->kerberos_auth ^ cfg->kerberos_onestep_auth )
     {
          ERROR( "UseSimpleBind, UseKerberosAuth, and UseKerberosOneStepAuth are mutually exclusive.  You can only specify one.\n" );
          return LDAP_CFG_ERROR;
     }

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
     if( cfg->kerberos_auth )
     {
          LDEBUG( LDAP_CFG_DEBUG_CNXN, "Auth Method = KRBV4\n" );
          auth_method = LDAP_AUTH_KRBV4;
     }
     else if( cfg->kerberos_onestep_auth )
     {
          LDEBUG( LDAP_CFG_DEBUG_CNXN, "Auth Method = KRBV4 OneStep\n" );
          auth_method = LDAP_AUTH_KRBV41;
     }
#else
     if( cfg->kerberos_auth || cfg->kerberos_onestep_auth )
     {
          ERROR( "LDAP Library was not compiled with Kerberos Bind support.\n" );
          return LDAP_CFG_ERROR;
     }
#endif // LDAP_API_FEATURE_X_OPENLDAP_VS_KBIND

     return ldap_cfg_ldap_bind_s( cfg, ldap_rec, auth_method );
} 




/*
  ldap_cfg_connect_bind_v3()
  
  Version 3 of the LDAP protocol supports the following bind methods:
  
  Simple and SASL, both with TLS support
*/
static int ldap_cfg_connect_bind_v3(
     ldap_cfg_srv_cfg * cfg,
     LDAP * ldap_rec )
{

     // Q: Shouldn't we check for SASL support?
     // A: Quiet, you

     // We default to SASL Authentication for V3
     int auth_method = LDAP_AUTH_SASL;
     
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_connect_bind_v3()\n" );
     LDEBUG( LDAP_CFG_DEBUG_CNXN, "Default Auth Method (v3) = SASL\n" );

     // TLS baby
     if( cfg->use_tls )
     {
          LDEBUG( LDAP_CFG_DEBUG_CNXN, "Starting TLS Session...\n" );
         if( ldap_start_tls_s( ldap_rec, NULL, NULL ) != LDAP_SUCCESS )
          {
               ldap_perror( ldap_rec, "UseTLS: ldap_start_tls_s" );
               return LDAP_CFG_ERROR;
          }
     }

     // Perhaps you would care for a simple bind?
     if( cfg->simple_bind )
     {
          auth_method = LDAP_AUTH_SIMPLE;
          LDEBUG( LDAP_CFG_DEBUG_CNXN, "Auth Method = Simple\n" );
          return ldap_cfg_ldap_bind_s( cfg, ldap_rec, auth_method );
     }

     // Prepare SASL Properties
     if( cfg->sasl_props != NULL
         &&
         ldap_set_option( ldap_rec,
                          LDAP_OPT_X_SASL_SECPROPS,
                          (void *) cfg->sasl_props )
         != LDAP_OPT_SUCCESS )
     {
          ERROR( "Could not set LDAP Sasl Properties: %s\n", cfg->sasl_props );
          return LDAP_CFG_ERROR;
     }

     LDEBUG( LDAP_CFG_DEBUG_CNXN,
             "ldap_sasl_interactive_bind_s\n(\n\n    bind_dn => \"%s\",\n    mech =>    \"%s\",\n    realm =>   \"%s\",\n    authc =>   \"%s\",\n    authz =>   \"%s\",\n    passwd =>  \"%s\"\n)\n",
             cfg->bind_dn,
             cfg->sasl_mech,
             cfg->sasl_realm,
             cfg->sasl_authc,
             cfg->sasl_authz,
             cfg->password );

     if( ldap_sasl_interactive_bind_s(
              ldap_rec,                // (LDAP *) object
              cfg->bind_dn,            // Bind DN
              cfg->sasl_mech,          // Valid SASL Mechanism
              NULL,                    // Server Controls
              NULL,                    // Client Controls
              LDAP_SASL_QUIET,         // SASL Flags - We want
                                       // non-interactive mode
              ldap_cfg_sasl_interact,  // Interactive SASL
                                       // callback... let's try
                                       // ignoring it
              (void *) cfg )           // This will get passed to the
                                       // ldap_cfg_sasl_interact
                                       // callback
         != LDAP_SUCCESS )
     {
          ldap_perror( ldap_rec, "SASL Bind Failure" );
          return LDAP_CFG_ERROR;                                   
     }

     return LDAP_CFG_OK;
}




/*
  ldap_cfg_sasl_interact()

  During SASL bind, the SASL callback structure will query us for a number
  of values such as Authentication ID, password, etc, depending on which
  SASL backend is being used.  This function iterates through these
  interaction requests, and hands them off to ldap_cfg_sasl_interaction()
  for processing.
*/
int ldap_cfg_sasl_interact(
     LDAP * ldap_rec,
     unsigned flags,
     void * data,
     void * in )
{
     sasl_interact_t * interact = in;
     
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_sasl_interact()\n" );

     while( interact->id != SASL_CB_LIST_END )
     {
          int rc = ldap_cfg_sasl_interaction( ldap_rec,
                                              flags,
                                              interact, 
                                              data );
          if( rc )  return rc;
          interact++;
     }
     LDEBUG( LDAP_CFG_DEBUG_SASL,
             "ldap_cfg_sasl_interact iteration complete\n" );
     return LDAP_SUCCESS;
}




/*
  ldap_cfg_sasl_interaction()

  As explained in ldap_cfg_sasl_interact(), this method sends responses to
  SASL interaction requests in the SASL bind sequence.  Typically, this
  includes info like the Authentication ID and password.
*/
static int ldap_cfg_sasl_interaction (
     LDAP * ldap_rec,
     unsigned flags,
     sasl_interact_t *interact,
     ldap_cfg_srv_cfg * cfg )
{
     const char * answer = interact->defresult;
     int opt;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_sasl_interaction()\n" );

     switch( interact->id )
     {

     case SASL_CB_GETREALM:

          LDEBUG( LDAP_CFG_DEBUG_SASL, "SASL Query: SASL_CB_REALM\n" );
          answer = cfg->sasl_realm;
          opt = LDAP_OPT_X_SASL_REALM;
          break;
          
     case SASL_CB_AUTHNAME:

          LDEBUG( LDAP_CFG_DEBUG_SASL, "SASL Query: SASL_CB_AUTHCID\n" );
          answer = cfg->sasl_authc;
          opt = LDAP_OPT_X_SASL_AUTHCID;
          break;
          
     case SASL_CB_PASS:

          LDEBUG( LDAP_CFG_DEBUG_SASL, "SASL Query: SASL_CB_PASS\n" );
          answer = cfg->password;
          opt = 0;                 // There is no default password
          break;
        
     case SASL_CB_USER:
          LDEBUG( LDAP_CFG_DEBUG_SASL, "SASL Query: SASL_CB_USER\n" );
          answer = cfg->sasl_authz;
          opt = LDAP_OPT_X_SASL_AUTHZID;
          break;

          
     default:
          LDEBUG( LDAP_CFG_DEBUG_SASL,
                  "No appropriate acction for SASL_CB: %d\n", interact->id );
          return LDAP_SUCCESS;
          break;
     }
     
     // Retrive default value?
     if( ( answer == NULL ) && opt )
     {
          LDEBUG( LDAP_CFG_DEBUG_SASL,
                  "Retrieving default value: ldap_get_option()\n" );
          ldap_get_option( ldap_rec, opt, &answer );
     }
     

     if( answer != NULL )
     {
          interact->result = strdup( answer );
     }
     else
     {
          interact->result = strdup( "" );
     }

     interact->len = interact->result
          ? strlen( interact->result ) : 0;

     LDEBUG( LDAP_CFG_DEBUG_SASL, "SASL Response: %s\n", interact->result );
     return LDAP_SUCCESS;
}






////
//
// [Attribute Stack management and Variable Substitution]
//
////




/*
  ldap_cfg_attr_parse_string_for_vars() parses a string looking for
  variables references of the form "$(#)", where # is a number
  indicating how far to look back in the attr stack.  In the course of
  searching, it breaks the string appart into tokens of variable and
  non-variable portions.  For example, given the string
  "aaa$(1)bbb$(2)ccc", this function will break it appart as "aaa",
  $(1), "bbb", $(2), "ccc".  These tokens are stored in a (char *)
  array as controlled by the array header parts->tokens_ah.  For
  posistions representing a variable instead of text, a NULL is put in
  the array instead of actual text.  As illustration, the previous
  example would be represented as "aaa", NULL, "bbb", NULL, "ccc".
  These empty slots will eventually be replaced by substituted
  variable values and the whole array will be concatenated to produce
  the final string.

  When a variable is parsed from the string, an entry is made in
  parts->positions, an array of integers.  The size of this array is
  equal to the number of previous searches that have been performed.
  Since each variable refers back to a previous search , $(1) the most
  recent, $(2) second most recent, etc., there should never be a
  variable higher in number than the total number of searches. Each of
  these previous searches will have a corresponding entry in the
  attribute stack.

  When a variable is found, its position in the token array is noted
  with the following code:

      parts->positions[ count - 1 ] |= ( 1 << parts->tokens_ah->nelts );
  
  where count is the variable number.  Going back to our example,
  "aaa$(1)bbb$(2)ccc" would first be parsed into the token "aaa",
  which would occupy the first position of the parts->tokens_ah array.
  The next token, $(1), is a variable.  It's 'count' is 1 and it
  occupies token position 1, which is the same as the value of
  parts->tokens_ah->nelts, since the number of elements increases as
  each token is pushed on.  Thus, the previous line of code would OR
  parts->positions[ 0 ] with a 2, which is 1 shifted 1-bit to the
  left.

  Thus, we get a quick and dirty index of where each variable needs to
  be substituted back into the token array.  For a string
  "a$(1)b$(2)c$(1)d", you'd get:

      positions[0] == 34 == ( 1 << 1 ) | ( 1 << 5 ) == 0100010    // Var $(1)
      positions[1] == 8  == ( 1 << 4 )              == 0001000    // Var $(2)

  In other words, it creates a [variable -> position] index, as
  opposed to the [position -> variable] index that is stored in the
  token array.  This will be important in the recursive substitution
  routine.
*/
int ldap_cfg_parse_string_for_vars(
     pool * p,
     array_header * ah,
     ldap_cfg_word_array * parts,
     const char * to_parse )
{
     int index = 0;            // Offset into the string to_parse
     int word_offset = 0;      // Offset indicating the begining of
                               // the latest word token
     int count;                // Will hold numeric name of variable
                               // when one is found
     int state = LDAP_CFG_FSM_INIT;

     LDEBUG( LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_attr_stack_parse_for_vars( to_parse => \"%s\" )\n",
             to_parse );

     // Prepare word_array
     parts->tokens_ah =  ap_make_array( p, 1, sizeof( char * ) );
     parts->positions = NULL;

     // Allocate array of ints for holding positions only if we have
     // anything in attr_stack to substitute in
     if( ah->nelts > 0 )
     {
          parts->positions = ap_pcalloc( p, sizeof( int ) * ah->nelts );
     }

     // Only parse if we have a string
     if( to_parse == NULL )
     {
          return LDAP_CFG_OK;
     }

     // A FSM to parse through the string looking for $(#'s) variables
     for( index=0; to_parse[ index ] != '\0'; index++ )
     {
          char token = to_parse[ index ];

          switch( state )
          {
          case LDAP_CFG_FSM_INIT:

               if( token == '$' )
               {
                    state = LDAP_CFG_FSM_VAR;
               }
               break;

          case LDAP_CFG_FSM_VAR:
               
               if( token == '(' )
               {
                    // Add word if we've got one
                    if( index - 1 > word_offset )
                    {
                         ldap_cfg_extract_word_token( p,
                                                      parts->tokens_ah,
                                                      to_parse + word_offset,
                                                      index - word_offset - 1);
                    }

                    state = LDAP_CFG_FSM_NUM;
                    count = 0;
               }
               else
               {
                    if( token == '$' )
                    {
                         ldap_cfg_extract_word_token( p,
                                                      parts->tokens_ah,
                                                      to_parse + word_offset,
                                                      index - word_offset );
                         word_offset = index + 1;
                    }

                    state = LDAP_CFG_FSM_INIT;
               }
               break;

          case LDAP_CFG_FSM_NUM:

               if( isdigit( token ) )
               {
                    count = ( count * 10 ) + ( ( (int) token ) - 48 );
               }
               else if( token == ')' )
               {
                    if( count > ah->nelts )
                    {
                         ERROR( "You have specified substition by variable $(%d) when you have not perfomed %d searches!\n", count, count );
                         return LDAP_CFG_ERROR;
                    }
                    else if( count < 0 )
                    {
                         ERROR( "Invalid variable name in \"%s\" at position %d.\n", to_parse, index );
                         return LDAP_CFG_ERROR;
                    }
                    else if( count == 0 )
                    {
                         char ** word_ptr;
                         // Hostname variable found $(0)
                         LDEBUG( LDAP_CFG_DEBUG_TODO,
                                 "Found hostname token: position => %d\n",
                                 parts->tokens_ah->nelts );

                         word_ptr = ap_push_array( parts->tokens_ah );
                         *(word_ptr) = getenv( "HOSTNAME" );

                         LDEBUG( LDAP_CFG_DEBUG_TODO, "Hostname: %s\n", *(word_ptr) );
                    }
                    else
                    {
                         // See docs above for a note on this craziness
                         parts->positions[ count - 1 ] |= ( 1 << parts->tokens_ah->nelts );
                         
                         LDEBUG( LDAP_CFG_DEBUG_TODO,
                                 "Found variable token: var => $(%d), position => %d\n",
                                 count, parts->tokens_ah->nelts );
                         
                         // Push an empty (char *) onto token array for
                         // later substitution by variable value
                         ap_push_array( parts->tokens_ah );

                    }

                    word_offset = index + 1;
                    state = LDAP_CFG_FSM_INIT;
               }
               else
               {
                    ERROR( "Invalid char '%c' found in variable name in string \"%s\" at position %d.\n", token, to_parse, index );
                    return LDAP_CFG_ERROR;
               }

               break;

          default:

               LDEBUG( LDAP_CFG_DEBUG_TODO, "Invalid state: %d\n", state );
               break;
          }
     }     

     // Catch a word that might have been left hanging
     if( index > word_offset )
     {
          ldap_cfg_extract_word_token( p,
                                       parts->tokens_ah,
                                       to_parse + word_offset,
                                       index - word_offset );
     }

     return LDAP_CFG_OK;
}          




/*
  ldap_cfg_extract_word_token()

  This method extracts a string of length 'length' from 'source' and adds it
  to the (char *) array specified by 'ah'.
*/
void ldap_cfg_extract_word_token(
     pool * p,
     array_header * ah,
     const char * source,
     int length )
{
     char ** word_ptr;
     word_ptr = ap_push_array( ah );
     *(word_ptr) = ap_pstrndup( p, source, length );
     
     LDEBUG( LDAP_CFG_DEBUG_TODO,
             "Found word token: token => \"%s\", position => %d\n",
             *word_ptr,
             ah->nelts - 1 );
}




/*
  ldap_cfg_attr_stack_add_values()

  This method takes a (char*) array of values and pushes them onto
  the attribute stack.  These values are usually the result of an
  'LDAPCfg_Search' command.
*/
void ldap_cfg_attr_stack_add_values(
     array_header * ah,
     char ** values )
{
     pool * p = ldap_cfg_attr_stack_pool; 
     int index;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_attr_stack_add_values()\n" );

     // Duplicate all the values into array
     for( index = 0; values[ index ] != NULL; index++ )
     {
          char ** word_ptr;
          word_ptr = ap_push_array( ah );
          *( word_ptr ) = ap_pstrdup( p, values[ index ] );
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "\t\tAdding new value onto attr stack: %s\n",
                  *( word_ptr ) );
     }
}




/*
  ldap_cfg_attr_stack_add_attr()

  After an "LDAPCfg_Search" directive produces new search results, we
  push them onto the attribute stack using this function.
*/
void ldap_cfg_attr_stack_add_attr (
     array_header * attr_stack,
     array_header * value_stack )
{
     if( value_stack != NULL )
     {
          // Pushing on new values from search
          array_header ** ah_ptr =
               ap_push_array( attr_stack );
          
          *( ah_ptr ) = value_stack;
     }
}




/*
  To understand how this function works, you must first understand how
  we perform variable substitutions.  Say the results of the previous
  search, corresponding to $(1), were "aa" and "bb".  The results of
  the search before that, corresponding to $(2), were "cc" and "dd".
  Now, the user has specified a search with a filter of
  "(&(cn=$(1))(objectclass=$(2)))".  What we want now is to perform
  searches using every combination of $(1) and $(2) together.  With 2
  values each, that gives us four (me math good).  To spell it out for
  you, we will actually perform four searches with the following
  filters:

      (&(cn=aa)(objectclass=cc))
      (&(cn=aa)(objectclass=dd))
      (&(cn=bb)(objectclass=cc))
      (&(cn=bb)(objectclass=dd))

  As you can see, we've got all the combinations represented.  But how
  do we generate all these combinations programatically?  Recursively
  of course.
  
  ldap_cfg_recursive_var_subst is called first with var_num set to the
  number of entries in the attr-stack (== # previous searches).  We
  then loop through each variable in descending order, decrementing
  var_num each time, until it's zero, at which point we perform the
  search.  The fun part comes in when we have multiple values for each
  variable.

  Say we add another search at $(3) to the example above with the
  values "ee" and "ff". We use a filter of "(attr=$(1)-$(2)-$(3))".
  The following diagram illustrates the sequence of recursive calls.
  Each column indicates a deeper level of recursive call, with the
  final column ( var_num == 0 ) indicating an actuall call to
  'ldap_cfg_perform_search', since the string has been completely
  substituted at this point.

  As you can see in column 1 (var_num == 3), there are two calls to
  ldap_cfg_recursive_var_subst, one for each value of $(3).  When all
  the calls are complete, you are level with eight calls to
  'ldap_cfg_perform_search', with a total of eight different
  combinations.  Que guay.


  var_num = 3         var_num = 2       var_num = 1     var_num = 0

  (attr=$(1)-$(2)-$(3))
                      (attr=$(1)-$(2)-ee)
                                        (attr=$(1)-cc-ee)
                                                        (attr=aa-cc-ee)
                                                        (attr=bb-cc-ee)
                                        (attr=$(1)-dd-ee)
                                                        (attr=aa-dd-ee)
                                                        (attr=bb-dd-ee)
                      (attr=$(1)-$(2)-ff)
                                        (attr=$(1)-cc-ff)
                                                        (attr=aa-cc-ff)
                                                        (attr=bb-cc-ff)
                                        (attr=$(1)-dd-ff)
                                                        (attr=aa-dd-ff)
                                                        (attr=bb-dd-ff)
  I hope that helps ; )
*/        
int ldap_cfg_recursive_var_subst(
     ldap_cfg_parms * args,
     ldap_cfg_word_array * base,
     ldap_cfg_word_array * filter,
     int var_num )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_recursive_var_subst()\n" );

     if( var_num == 0 )
     {
          // If var_num equals zero, we have run through all the
          // variables and are ready to perform the search

          return ldap_cfg_perform_search( args, base, filter );
     }
     else
     {
          // If we have a hit on this variable for either filter or
          // base, perform substitution.  Otherwise, move onto the
          // next next variable directly

          if( base->positions[ var_num - 1 ] ||
              filter->positions[ var_num - 1 ] )
          {
               array_header ** ah_ptr = (array_header **) args->attr_ah->elts;
               int elt_num = args->attr_ah->nelts - var_num;
               char ** elts = ( char ** ) ah_ptr[ elt_num ]->elts;
               int index;

               // Here is where the recursive calls start to pile up.
               // We loop through all the values for a given variable,
               // performing the substitution and moving onto the next
               // recursive level for each.  Thus, when we finish, we
               // will have substituted every possible variable
               // combination.
               
               for( index = 0; index < ah_ptr[ elt_num ]->nelts; index++ )
               {
                    LDEBUG( LDAP_CFG_DEBUG_TODO,
                            "Replacing all occurences of $(%d) with \"%s\"\n",
                            var_num, elts[ index ] );

                    // Substitute single variable for base and filter
                    ldap_cfg_single_var_subst(
                         base->positions[ var_num - 1 ],
                         (char ** )base->tokens_ah->elts,
                         elts[ index ] );

                    ldap_cfg_single_var_subst(
                         filter->positions[ var_num - 1 ],
                         (char **)filter->tokens_ah->elts,
                         elts[ index ] );

                    // Move on to next variable
                    if( ldap_cfg_recursive_var_subst( args,
						      base,
						      filter,
						      var_num - 1 )
			!= LDAP_CFG_OK )
		    {
			 return LDAP_CFG_ERROR;
		    }
               }
          }
          else
          {
               return ldap_cfg_recursive_var_subst( args, base, filter, var_num - 1 );
          }
     }
}




/*
  ldap_cfg_single_var_subst()

  This function determines if a given variable needs to be substituted
  with values ( pos_set != 0 ).  If so, it loops through the positions
  indicated in 'pos_set' and substitutes the equivalent position in
  'tokens' with 'elt'.
*/
void ldap_cfg_single_var_subst(
     int pos_set,
     char ** tokens,
     char * elt )
{
     if( pos_set )
     {
          int pos = 0;
          
          for( ; ( pos_set >> pos ) > 0 ; pos++ )
          {
               if( ( pos_set >> pos ) & 1 )
               {
                    tokens[ pos ] = elt;
               }
          }
     }
}





////
//
// LDAP Search Routines
//
////




/*
  ldap_cfg_perform_search()

  This method creates the final 'base' and 'filter' strings and calls
  the 'ldap_search_s' routine to perform an actual search.  The
  results are sent to the callback routine 'args->call_back'.
*/
int ldap_cfg_perform_search(
     ldap_cfg_parms * args,
     ldap_cfg_word_array * base,
     ldap_cfg_word_array * filter )
{
     LDAPMessage * res;
     char * base_s =  ldap_cfg_array_pstrcat( args->mem_pool,
                                              base->tokens_ah );
     char * filter_s =  ldap_cfg_array_pstrcat( args->mem_pool,
                                                filter->tokens_ah );

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_perform_search()\n" );
     LDEBUG( LDAP_CFG_DEBUG_SRCH,
             "ldap_search_s( base => \"%s\", filter => \"%s\", scope => %d )\n",
             base_s, filter_s, args->scope );

             
     if( ldap_search_s( args->ldap_rec,   // LDAP object
                        base_s,           // Base DN to search against
                        args->scope,      // Scope of search: LDAP_SCOPE_*
                        filter_s,         // Search filter
                        args->attr_list,  // List of attrs to return.
                                          // Returns all of them if
                                          // NULL
                        0,                // We don't want Attribute Names only
                        & res )           // Will hold result set
         != LDAP_SUCCESS )
     {
          ldap_perror( args->ldap_rec, "LDAP Search failed" );
          // DEBUG( "Unbinding LDAP connection\n" );
          // ldap_unbind( args->ldap_rec );
          return LDAP_CFG_ERROR;
     }
          
     // Call the callback
     ( ( int (*) ( ldap_cfg_parms *, LDAPMessage * ) )
       args->call_back )( args, res );
     
     // Free LDAPMessage
     LDEBUG( LDAP_CFG_DEBUG_TODO, "ldap_msgfree()\n" );
     ldap_msgfree( res );     

     return LDAP_CFG_OK;
}

/*
  ldap_cfg_sort_entries()

  For processing configuration directives, it is important that they
  be sorted by DN.  Considering they come back from LDAP in arbitrary
  order, we sort them here.  For example, if we had the following DN's:
  
  t=a,t=b,t=c
  t=a,t=c
  t=b,t=b,t=c  
  t=c
  t=b,t=a,t=c

  We should get something like then when we are done sorting:

            t=c
       t=a, t=c
  t=b, t=a, t=c
  t=a, t=b, t=c
  t=b, t=b, t=c

  Basically, the items are sorted into 'depth-first' tree.  This
  sorting is neccessary for our <Section> functionality, which says
  that all objects which are children of a <Section> object should be
  contained within that section.

  Sorting is performed off of the exploded DN using the stdlib qsort
  function and the comparison function, ldap_cfg_reverse_dn_cmp().

  Note that we explode the DN and count the number of entries here,
  saving it in the ldap_cfg_dn_entry struct for later use when
  processing <Section> objects and in the comparison function.
*/
int ldap_cfg_sort_entries(
     pool * p,
     LDAP * ld,
     LDAPMessage * msg,
     ldap_cfg_dn_entry ** entries_ptr )
{
     int index, count;
     ldap_cfg_dn_entry * entries;
     LDAPMessage * single_entry;
     LDAPMessage * e;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_sort_entries()\n" );
     
     count = ldap_count_entries( ld, msg );
     LDEBUG( LDAP_CFG_DEBUG_SRCH, "Number of entries returned: %d\n", count );

     LDEBUG( LDAP_CFG_DEBUG_TODO,
             "Allocating ldap_cfg_dn_entry array for %d entries...\n",
             count );
     entries = ap_pcalloc( p, sizeof( ldap_cfg_dn_entry ) * count );

     single_entry = ldap_first_entry( ld, msg );

     LDEBUG( LDAP_CFG_DEBUG_TODO, "Popluating entries array...\n" );
     for ( index = 0; index < count; index++ )
     {
          int count = 0;
          char * dn = ldap_get_dn( ld, single_entry );

          entries[ index ].msg = single_entry;
          entries[ index ].ex_dn = ldap_explode_dn( dn, 0 );
          while( entries[ index ].ex_dn[ count ] != NULL ) count++;
          entries[ index ].dn_count = count;

          ldap_memfree( dn );	  
          single_entry = ldap_next_entry( ld, single_entry );
     }

     LDEBUG( LDAP_CFG_DEBUG_TODO, "qsort()\n" );
     qsort( entries,
            count,
            sizeof( ldap_cfg_dn_entry ),
            ldap_cfg_reverse_dn_cmp );

     (* entries_ptr ) = entries;
     return count;
}               




/*
  ldap_cfg_reverse_dn_cmp()

  Given to ldap_cfg_dn_entry objects, it determines which object
  should be sorted first by doing a reverse comparison of their DN's.
  The entries should be organized that a parent object should come
  before its child.  See the example listed for ldap_cfg_sort_entries
  for an example.  This function is passed to qsort in
  ldap_cfg_sort_entries.
*/
int ldap_cfg_reverse_dn_cmp(const void * a, const void *b)
{
     ldap_cfg_dn_entry * msg_a = (ldap_cfg_dn_entry *) a;
     ldap_cfg_dn_entry * msg_b = (ldap_cfg_dn_entry *) b;

     char ** ex_a = msg_a->ex_dn;
     char ** ex_b = msg_b->ex_dn;

     int len_a = msg_a->dn_count;
     int len_b = msg_b->dn_count;
     int retro = 0;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_reverse_dn_cmp()\n" );

     // If neither DN has any entries then they are the same
     if( ! ( len_a || len_b ) )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO,
                  "Neither A nor B have any entries...\n" );
          retro = 0;
     }
     // If only one has no entries, it goes first
     else if( ( len_a > 0 ) ^ ( len_b > 0 ) )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO,
                  "One of the entries has zero length...\n" );
          retro = ( len_b > 0 ) ? -1 : 1;
     }
     else
     {
          // Loop in reverse order through the DN until we find a
          // difference
          while( ! retro )
          {
               retro = strcmp( ex_a[ --len_a ], ex_b[ --len_b ] );
               
               // If we have found no difference, but one DN is out of
               // entries, the one that has run out goes first.
               if( ! retro &&
                   ( ( len_a > 0 ) ^ ( len_b > 0 ) ) )
               {
                    retro = ( len_b > 0 ) ? -1 : 1;
               }
          }
     }

     return retro;
}





////
//
// Result processing call-backs
//
////




/*
  ldap_cfg_cb_search()
  
  This result processing call-back is used by 'LDAPCfg_Search' to
  iterate through the result set and save all the values of the user
  specified attribute.
*/
int ldap_cfg_cb_search (
     ldap_cfg_parms * args,
     LDAPMessage * res )
{
     LDAPMessage * msg = res;
     LDAPMessage * single_rec;
     BerElement * attr_ptr;
     array_header * ah, ** ah_ptr;
     int just_dn = 0;
     char * attr_name = NULL;
     ldap_cfg_dn_entry * entries;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_cb_search()\n" );


     // If we have multi-value variable substituions on our search
     // string, we will have to combine all the various values to be
     // saved across multiple searches.  We might even be in the
     // middle of a search now.  Thus, create a new array to save in
     // if it doesn't exist already.  Otherwise, leave it be.
     if( args->call_back_data == NULL )
     {
          ah = ap_make_array( ldap_cfg_attr_stack_pool, 2, sizeof( char * ) );
          args->call_back_data = ah;
     }
     else
     {
          ah = args->call_back_data;
     }

     // If res == NULL, we have been called in clean-up mode.  Add all
     // accumulated values as a new entry in the attribute stack
     if( res == NULL )
     {
          ldap_cfg_attr_stack_add_attr( args->attr_ah, ah );
          return LDAP_CFG_OK;
     }

     // Determine which attribute the user wishes to save
     if( args->attr_list != NULL )
     {
          attr_name = args->attr_list[ 0 ];
          just_dn = ( strcmp( "1.1", attr_name ) == 0 );
          LDEBUG( LDAP_CFG_DEBUG_SRCH,
                  "Will be saving attribute: \"%s\"\n",
                  attr_name );
     }


     // Loop through each record and process the results
     for( single_rec = ldap_first_entry( args->ldap_rec, msg );
          single_rec != NULL;
          single_rec = ldap_next_entry( args->ldap_rec, single_rec ) )
     {
          char * dn = ldap_get_dn( args->ldap_rec, single_rec );

          LDEBUG( LDAP_CFG_DEBUG_SRCH, "\tdn: %s\n", dn );

          if( just_dn )
          {
               char * values[2];
               values[0] = dn;
               values[1] = NULL;
               ldap_cfg_attr_stack_add_values( ah, values );
          }
          else
          {
               char ** values = ldap_get_values( args->ldap_rec,
                                                 single_rec,
                                                 attr_name );
               if( values != NULL )
               {
                    ldap_cfg_attr_stack_add_values( ah, values );
               }
               ldap_value_free( values );
          }

          ldap_memfree( dn );
     }

      
     if( ah->nelts < 0 )
     {
          ERROR( "No results from search!\n" );
          return LDAP_CFG_ERROR;
     }

     return LDAP_CFG_OK;
}




/*
  ldap_cfg_cb_load()

  This results processing call-back handles a result set created by
  the 'LDAPCfg_Load' command.  It sorts the results by reverse-DN and
  then sends on any Apache configuration directives it finds.
*/
int ldap_cfg_cb_load (
     ldap_cfg_parms * args,
     LDAPMessage * res )
{
     ldap_cfg_dn_entry * entries;
     ldap_cfg_config_stack * config_stack;
     int count, index;
     

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_cb_load()\n" );

     if( res == NULL )
     {
          return ldap_cfg_apache_command_loop( args );
     }

     // If this is our first time through, we need to initialize our
     // data structures
     if( args->call_back_data == NULL )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO, "Preparing config stack\n" );
          args->call_back_data = ap_pcalloc( args->mem_pool,
                                             sizeof( ldap_cfg_config_stack ) );
          config_stack = args->call_back_data;
          config_stack->config_ah = ap_make_array( args->mem_pool,
                                                   4,
                                                   sizeof( char * ) );
          config_stack->index = 0;
     }

     // Reset <Section> stack portion of config stack before starting
     config_stack = args->call_back_data;
     config_stack->section_stack = NULL;
     config_stack->section_depth = 0;

     count = ldap_cfg_sort_entries( args->mem_pool,
                                    args->ldap_rec,
                                    res,
                                    & entries );
     
     for( index = 0; index < count; index ++ )
     {
          LDAPMessage * msg = entries[ index ].msg;
          char * dn;

          dn = ldap_get_dn( args->ldap_rec, msg );
          LDEBUG( LDAP_CFG_DEBUG_SRCH, "\tdn: %s\n", dn );
          ldap_memfree( dn );

          if( ldap_cfg_handle_config_obj( args, & entries[ index ] ) )
          {
               return LDAP_CFG_ERROR;
          }
     }

     return ldap_cfg_check_section_stack( args, NULL );
}






////
//
// Configuration processing
//
////



/*
  ldap_cfg_handle_config_obj()

  This function examines an LDAP record to determine what type of
  configuration object it is.  If it is an ApacheSectionObj, we handle
  it differently than a regular configuration object.
*/
int ldap_cfg_handle_config_obj (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry )
{
     int retro;

     LDEBUG( LDAP_CFG_DEBUG_FUNC,
             "ldap_cfg_handle_config_obj()\n" );

     // Do need to close off an old section?
     ldap_cfg_check_section_stack( args, entry );

     // Do we have a new section?
     if( ldap_cfg_is_section_obj( args->ldap_rec, entry->msg ) )
     {
          ldap_cfg_config_stack * config_stack = args->call_back_data;

          // Add entry to the stack
          entry->prev = config_stack->section_stack;
          config_stack->section_stack = entry;

          retro = ldap_cfg_hanlde_section_obj( args, entry );
          config_stack->section_depth++;

          // Process any remaining config directives
          if( retro == LDAP_CFG_OK )
          {
               retro = ldap_cfg_handle_plain_obj( args, entry, 1 );
          }

     }
     else
     {
          // Handle regular entry
          retro = ldap_cfg_handle_plain_obj( args, entry, 0 );
     }

     return retro;
}
          


               
/*
  ldap_cfg_handle_section_obj()

  This function handles "ApacheSectionObj" objects.  These objects are
  used to model Apache "<Sections></Sections>".  The object has
  attributes "ApacheSectionName" and "ApacheSectionArg" which will
  become "<ApacheSectionName ApacheSectionArg></ApacheSectionName>".
  
  Another important feature is that all sub-records of the section
  object will be processed within that section.  That is if you had
  the following records:

  dn: tag=a, dc=test
  objectClass: ApacheSectionObj
  ApacheSectionName: VirtualHost
  ApacheSectionArg: 192.168.1.1

  dn tag=kid, tag=a, dc=test
  objectclass: ApacheVirtualHost
  ApacheServerName: test.com

  You would get the following equivalent configuration:

  <VirtualHost 192.168.1.1 >
      ServerName test.com
  </VirtualHost>

  We do this by keeping a reverse-linked list of all currently open
  sections using the 'prev' field of the ldap_cfg_dn_entry object
  representing the section.  The list is actually linked up back in
  'ldap_cfg_handle_config_obj'.  There are a number of support
  routines that deal with closing off the sections and what not.
*/
int ldap_cfg_hanlde_section_obj (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry )
{
     char ** values;
     char * section_name;
     char config_string[150];
     char * sec_name = LDAP_CFG_SECTION_NAME;
     char * sec_arg = LDAP_CFG_SECTION_ARG;
     
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_handle_section_obj()\n" );

     // Grab Section Name
     values = ldap_get_values( args->ldap_rec,
                               entry->msg,
                               LDAP_CFG_SECTION_NAME );

     if( ! ldap_count_values( values ) )
     {
          ERROR( "You must declare an %s attribute for a %s\n",
                 LDAP_CFG_SECTION_NAME,
                 LDAP_CFG_SECTION_OBJ );
          ldap_value_free( values );
          return LDAP_CFG_ERROR;
     }

     section_name = ap_pstrdup( args->mem_pool, values[0] );
     entry->section_name = section_name;

     ldap_value_free( values );
     
     // Grab Section argument

     values = ldap_get_values( args->ldap_rec, entry->msg, sec_arg );

     if( ldap_count_values( values ) )
     {
          snprintf( config_string, 149, "<%s %s >", section_name, values[0] );
     }
     else
     {
          snprintf( config_string, 149, "<%s >", section_name );
     }

     ldap_value_free( values );

     // Send actual config
     if( ldap_cfg_handle_command( args, config_string )
         != LDAP_CFG_OK )
     {
          return LDAP_CFG_ERROR;
     }

     return LDAP_CFG_OK;
}




/*
  ldap_cfg_handle_plain_obj()

  This function handle configuration directives in a plain
  configuration object (aka not a section object).  Processing is
  pretty simple.  We loop through all the attributes, and if the first
  letters are "Apache", it's an Apache configuration directive.  We
  strip the "Apache" and send on "ConfigDir Value".  The only special
  cases are:

  ApacheRawArg: So that a user can specify new config directives
  without having to modify the LDAP schema, we provide this attribute.
  Instead of stripping Apache from the attribute name and using RawArg
  as the directive name, we just send the contents of the value as is.
  That way you can specify anything you want and have it send on to
  Apache.

  '--' in the Attribute Name: There are a few Apache directives that
  use '_' in their name.  However, LDAP attributes are not allowed to
  use this character.  Thus, we will convert any appearance of '--' to
  '_' in the attribute name, since ;-' characters are allowed.
*/
int ldap_cfg_handle_plain_obj(
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry,
     int section_check )
{
     BerElement * ber;
     char * attr;
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_handle_plain_obj()\n" );
     
     // Loop through all of the attributes... 
     for( attr = ldap_first_attribute( args->ldap_rec, entry->msg, & ber );
          attr != NULL;
          attr = ldap_next_attribute( args->ldap_rec, entry->msg, ber ) )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO, "Checking attr \"%s\"...\n", attr );

          // First make sure that it is an "Apache" directive.
          // Secondly, if "section_check" is set, make sure that it is
          // not a "Section" attribute.
          if( ldap_cfg_is_apache_dir( attr ) &&
              ! ( section_check &&
                  ldap_cfg_is_section_attr( attr + LDAP_CFG_PREFIX_LENGTH )
                   ) )
 
          {
               char * config_dir = attr + LDAP_CFG_PREFIX_LENGTH;
               char * config_string[150];
               char ** values = ldap_get_values( args->ldap_rec,
                                                 entry->msg,
                                                 attr );
               int index = 0;
               int is_raw_arg = ldap_cfg_is_raw_arg( config_dir );

               // '--' -> '_'
               ldap_cfg_underscore_convert( config_dir );
               
               while( values[ index ] != NULL )
               {
                    char config_string[ 150 ];
                    if( is_raw_arg )
                    {
                         snprintf( config_string, 149,
                              "%s", values[ index ] );
                    }
                    else
                    {
                         snprintf( config_string, 149,
                                   "%s %s",
                                   config_dir,
                                   values[ index ] );
                    }
                    
                    if( ldap_cfg_handle_command( args, config_string )
                        != LDAP_CFG_OK )
                    {
                         ldap_value_free( values );
                         ber_free( ber, 0 );
                         return LDAP_CFG_ERROR;
                    }
                    index ++;
               }

               ldap_value_free( values );
          }
     }

     ber_free( ber, 0 );
               
     return LDAP_CFG_OK;
}




/*
  ldap_cfg_hanle_command()

  Given an actual Apache configuration directive, we push it onto the
  the config stack, which will all be sent to Apache in a custom
  configfile_t.  See ldap_cfg_apache_command_loop for more info.
*/
int ldap_cfg_handle_command (
     ldap_cfg_parms * args,
     const char * config_string )
{
     ldap_cfg_config_stack * config_stack = args->call_back_data;
     char ** word_ptr;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_handle_command()\n" );

     // Debug Output
     LDEBUG( LDAP_CFG_DEBUG_LINE, "%2d: ", config_stack->config_ah->nelts + 1);
     ldap_cfg_print_offset( config_stack->section_depth * LDAP_CFG_TAB_LENGTH,
			    LDAP_CFG_DEBUG_CFG | LDAP_CFG_DEBUG_LINE );
     LDEBUG( LDAP_CFG_DEBUG_CFG | LDAP_CFG_DEBUG_LINE,
             "%s\n", config_string );

     word_ptr = (char **) ap_push_array( config_stack->config_ah );
     (*word_ptr) = ap_pstrdup( args->mem_pool, config_string );

     return LDAP_CFG_OK;
}




/*
  ldap_cfg_apache_command_loop()
  
  This is where the rubber meets the road.  We create a custom
  configfile_t, which we will feed to ap_srm_command_loop.  Normally,
  that API call is used to iterate through config files, but our
  configfile_t will iterate through the accumulated configuration
  directives in the ldap_cfg_config_stack stored in
  args->call_back_data.

  Pretty cool, eh?
*/
int ldap_cfg_apache_command_loop (
     ldap_cfg_parms * args )
{
     const char * err_msg;
     configfile_t fake_file;
     configfile_t * old_config;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_apache_command_loop()\n" );

     // Prep our configfile
     fake_file.getstr = ldap_cfg_ah_getstr;
     fake_file.param = args->call_back_data;
     fake_file.name = "LDAP Configuration";
     fake_file.line_number = 0;
     fake_file.getch = NULL;
     fake_file.close = NULL;
     
     old_config = args->parms->config_file;
     args->parms->config_file = & fake_file;

     err_msg = ap_srm_command_loop( args->parms,
                                    args->parms->server->lookup_defaults );

     args->parms->config_file = old_config;

     if( err_msg != NULL )
     {
          ldap_cfg_config_stack * config_stack = args->call_back_data;
          char ** elts = (char **) config_stack->config_ah->elts;
          
          ERROR( "Syntax error: %s\n", err_msg );
          ERROR( "Configuration directive specified: %s\n",
                 elts[ config_stack->index - 1 ] );
          ERROR( "Line number: %d\n", config_stack->index );

          return LDAP_CFG_ERROR;
     }

     return LDAP_CFG_OK;
}



/*
  ldap_cfg_ah_getstr()

  The key to faking out Apache is this function.  Normally,
  configfile_t->getstr is a pointer to a fgets()-like function.  But
  we don't want to read from a file... we want to read from an
  ldap_cfg_config_stack->config_ah array_header.  And that's what our
  ldap_cfg_ah_getstr does.  Note that the ldap_cfg_config_stack is
  passed as a (void *) in 'param'.
*/
static void * ldap_cfg_ah_getstr (
     void * buf,
     size_t bufsiz,
     void * param )
{
     ldap_cfg_config_stack * config_stack = param;
     char ** elts = (char **) config_stack->config_ah->elts;
     char * sbuf = buf;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_ah_getstr()\n" );
     
     // Check to see if we're out of directive to send
     if( config_stack->index >= config_stack->config_ah->nelts )
     {
          LDEBUG( LDAP_CFG_DEBUG_TODO, "No more directives to send.\n" );
          return NULL;
     }

     strncpy( sbuf, elts[ config_stack->index++ ], bufsiz );

     LDEBUG( LDAP_CFG_DEBUG_TODO, "Sending Apache \"%s\" as line %d.\n", buf, index );

     return buf;
}



////
//
// Configuration processing support routines
//
////




/*
  ldap_cfg_is_section_obj()

  This method is used to determine if an LDAP record represents an
  ApacheSectionObj.  We determine this by looping through the values
  of 'objectclass' and looking for 'ApacheSectionObj".
*/
int ldap_cfg_is_section_obj (
     LDAP * ld,
     LDAPMessage * entry )
{
     char ** values = ldap_get_values( ld, entry, "objectclass" );
     int index = 0;
     int retro = 0;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_is_section_obj()\n" );

     while( values[ index ] != NULL )
     {
          if( ! strcmp( values[ index++ ], LDAP_CFG_SECTION_OBJ ) )
          {
               retro = 1;
          }
     }

     ldap_value_free( values );

     return retro;
}




/*
  ldap_cfg_check_section_stack()

  As stated in ldap_cfg_handle_section_obj(), all sub-entries of a
  ApacheSectionObj should be processed within the scope of that
  section.  However, once all these entries have been processed, we
  need to close of the section and move onto grener pastures.

  This function checks to see if the current entry is still within the
  scope of the section.  If not, it closes of the section (
  "</Section>" ) and adjusts the section stack appropriately.  Passing
  in a NULL entry will effectively close off all open sections.
*/
int ldap_cfg_check_section_stack (
     ldap_cfg_parms * args,
     ldap_cfg_dn_entry * entry )
{
     ldap_cfg_config_stack * config_stack = args->call_back_data;
     ldap_cfg_dn_entry * section = config_stack->section_stack;
     char config_string[150];

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_check_section_stack()\n" );

     while( section != NULL )
     {
          // We don't close the section unless we have an entry that
          // is a sub-entry of the active section.  However, if we
          // don't have a sub-entry, we close off the current section.
          // Passing a NULL value is a good way to close off all open
          // sections.
          if( entry != NULL &&
              ldap_cfg_is_sub_dn( section, entry ) )
          {
               return LDAP_CFG_OK;
          }

          // Increment before sending command so DEBUG output will look right
          config_stack->section_depth--;
          snprintf( config_string, 149, "</%s>", section->section_name );
          
          // Send actual config
          if( ldap_cfg_handle_command( args, config_string )
              != LDAP_CFG_OK )
          {
               return LDAP_CFG_ERROR;
          }
          
          // Pop one off the stack
          section = section->prev;
          config_stack->section_stack = section;
     }
     
     return LDAP_CFG_OK;
}




/*
  ldap_cfg_is_sub_dn()

  This function determines whether "child" is a sub-entry of parent.
  It does this by comparing the exploded DN's of the two entries in
  reverse order.  If it is a sub-entry, the parent will run out of DN
  components before the child and all of the parent's components will
  match the child's.
*/
int ldap_cfg_is_sub_dn (
     ldap_cfg_dn_entry * parent,
     ldap_cfg_dn_entry * child )
{
     int index = 0;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_Cfg_is_sub_dn()\n" );

     while( parent->ex_dn[ index ] != NULL )
     {
          if( child->ex_dn[ index ] == NULL ) return 0;
          if( ! strcmp( parent->ex_dn[ index ],
                        child->ex_dn[ index ] ) ) return 0;
          index++;
     }

     return 1;
}

               


/*
  ldap_cfg_is_apache_dir()

  This method examines a string to determine if it is naming an Apache
  configuration directive.  If it is a directive, it will be prefixed
  with "Apache".
*/
int ldap_cfg_is_apache_dir (
     const char * dir )
{
     char * test = LDAP_CFG_PREFIX;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_is_apache_dir()\n" );

     if( dir == NULL ) return 0;

     return ! strncmp( test, dir, LDAP_CFG_PREFIX_LENGTH );
}




/*
  ldap_cfg_is_raw_arg()

  Though the provided Apache LDAP schema provides entries for all
  configuration directives in the core httpd, the user may sometime
  wish to supply a custom directive without adding it to the schema.
  Thus, "ApacheRawArg", which passes the associated value onto Apache
  no questions asked.  This function determines if a given attribute
  is "RawArg"
*/
int ldap_cfg_is_raw_arg (
     const char * dir )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_is_raw_arg()\n" );

     if( dir == NULL ) return 0;

     return ! strncmp( "RawArg", dir, 6 );
}




/*
  ldap_cfg_is_section_attr()

  This method determines if the supplied string is either
  "SectionName" or "SectionArg", indicating that it is an attribute
  used by an "ApacheSectionObj".
*/
int ldap_cfg_is_section_attr (
     const char * dir )
{
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_is_section_attr( dir => \"%s\")\n", dir );    

     if( dir == NULL ) return 0;

     return  ! ( strncmp( "Section", dir, 7 ) ||
                 ( strncmp( "Arg", dir + 7, 3 ) &&
                   strncmp( "Name", dir + 7, 4 ) ) );
}




/*
  ldap_cfg_underscore_convert()

  LDAP attributes aren't allowed to have the '_' character, which
  causues a problem when we try to make a schema with
  "ApacheAnonymous_*" and other similar configuration directives.  So,
  I decided to use '--' instead.  The Apache LDAP Schema lists
  "ApacheAnonymous--*", and this function converts all '--' to '_'.
  God help us if someone uses '--' in a config directive.
*/
void ldap_cfg_underscore_convert (
     char * to_convert )
{
     int index = 0;
     int shift = 0;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_underscore_convert()\n" );

     if( to_convert == NULL ) return;

     for( ; to_convert[ index ] != '\0'; index++ )
     {
          // Note that while our current character has already been
          // shifted if necessary, the next one has not.  Thus, we
          // have to look for the second '-' using the shift.
          if( to_convert[ index ] == '-' &&
              to_convert[ index + 1 + shift ] == '-' )
          {
               LDEBUG( LDAP_CFG_DEBUG_TODO,
                       "Converting '--' to '_' at position [%d] in string \"%s\"",
                       index,
                       to_convert );
               to_convert[ index ] = '_';
               shift++;
          }

          // If we have a shift, we need to move each character down
          // as we move through
          if( shift )
          {
               to_convert[ index + 1 ] = to_convert[ index + 1 + shift ];
          }
     }
}
            

     





////
//
// Utility Functions
//
////  


/*
  ldap_cfg_print_offset()

  This function will print 'depth' number of spaces using
  'debug_level' as the debug level to LDEBUG
*/
void ldap_cfg_print_offset( int depth, int debug_level )
{
     int index = 0;
 
     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_print_offset()\n" );

     for( ; index < depth; index++ )
     {
          LDEBUG( debug_level, " " );
     }
}
     


/*
  ldap_cfg_array_pstrcat()

  Kind of a replacement for ap_array_pstrcat().  The basic idea is,
  given an array of (char *) strings, to concatenate them into a full
  string.  However, ap_array_pstrcat() wants you to put some text in
  between each element.  I don't want ANY text, so I wrote my own
  version.  It just concatentates everything together.
*/
char * ldap_cfg_array_pstrcat( pool * p, array_header * ah )
{
     char * final, ** elts;
     int index = 0;
     int length = 0;

     LDEBUG( LDAP_CFG_DEBUG_FUNC, "ldap_cfg_array_pstrcat()\n" );

     if( ah->nelts <= 0 || ah->elts == NULL )
     {
          //return (char *) ap_pcalloc(p, 1);
          return NULL;
     }

     elts = (char **) ah->elts;

     for( ; index < ah->nelts; index++ )
     {
          char * element;
          element = elts[ index ];
          if( element != NULL )
          {
                    length += strlen( element );
          }
     }

     final = ap_pcalloc( p, sizeof( char ) * ( length + 1 ) );
     length = 0;

     for( index = 0; index < ah->nelts; index++ )
     {
          char * element = elts[ index ];
          int sub_len = 0;
          int sub_index = 0;

          if( element != NULL )
          {
               sub_len = strlen( element );
          }

          for( ; sub_index < sub_len; sub_index++ )
          {
               final[ length ] = element[ sub_index ];
               length++;
          }
     }
      
     return final;
}


     


















/*
  Look at all the LDAPCfg Configuration directives... bleh.
*/

static const command_rec ldap_cfg_cmds[] =
{  
     // Connection Directives
     {  
          "LDAPCfg_BindDN", ldap_cfg_binddn_cmd,  
          NULL, RSRC_CONF, TAKE1,  
          "DN to bind to LDAP Directory with", 
     },

     {  
          "LDAPCfg_Password", ldap_cfg_password_cmd,  
          NULL, RSRC_CONF | ACCESS_CONF, TAKE1,  
          "DN to bind to LDAP Directory with", 
     },
  
     { 
          "LDAPCfg_Host", ldap_cfg_host_cmd,
          NULL, RSRC_CONF, TAKE12, 
          "Host host_name [port] to connect to"
     }, 
     
     { 
          "LDAPCfg_URI", ldap_cfg_uri_cmd,
          NULL, RSRC_CONF, TAKE1,
          "LDAP Uniform Resource Identifier"
     }, 

     {
          "LDAPCfg_ProtoVer", ldap_cfg_version_cmd,
          NULL, RSRC_CONF, TAKE1,
          "LDAP Protocol Version"
     },

     // SASL-Specific Directives

     { 
          "LDAPCfg_SASLAuthc", ldap_cfg_sasl_authc_cmd,
          NULL, RSRC_CONF, TAKE1, 
          "SASL Authentication ID"
     },

     { 
          "LDAPCfg_SASLAuthz", ldap_cfg_sasl_authz_cmd,
          NULL, RSRC_CONF, TAKE1, 
          "SASL Authorization ID"
     }, 

     { 
          "LDAPCfg_SASLRealm", ldap_cfg_sasl_realm_cmd,
          NULL, RSRC_CONF, TAKE1, 
          "SASL Realm"
     },

     { 
          "LDAPCfg_SASLMech", ldap_cfg_sasl_mech_cmd,
          NULL, RSRC_CONF, TAKE1, 
          "SASL Mechanism"
     },

     { 
          "LDAPCfg_SASLProps", ldap_cfg_sasl_props_cmd,
          NULL, RSRC_CONF, RAW_ARGS, 
          "SASL Authentication Properties"
     },

     /* Options */

     { 
          "LDAPCfg_UseSimpleBind", ldap_cfg_simple_bind_cmd,
          NULL, RSRC_CONF, NO_ARGS, 
          "Use simple authentication to bind"
     },

     { 
          "LDAPCfg_UseKerberosAuth", ldap_cfg_kerberos_bind_cmd,
          NULL, RSRC_CONF, NO_ARGS, 
          "Use Kerberos authentication to bind"
     },

     { 
          "LDAPCfg_UseKerberosOneStepAuth", ldap_cfg_kerberos_onestep_bind_cmd,
          NULL, RSRC_CONF, NO_ARGS,
          "Use Kerberos authentication to bind"
     },
     
     { 
          "LDAPCfg_UseTLS", ldap_cfg_tls_cmd,
          NULL, RSRC_CONF, NO_ARGS, 
          "Use Transport Layer Security"
     },

     /* Search Operations */

     { 
          "LDAPCfg_SearchScope", ldap_cfg_search_scope_cmd,
          NULL, RSRC_CONF | ACCESS_CONF, TAKE1, 
          "Seach scope: base, one, or sub"
     },

     { 
          "LDAPCfg_BaseDN", ldap_cfg_base_dn_cmd,
          NULL, RSRC_CONF | ACCESS_CONF, TAKE1, 
          "Base DN to search from"
     },

     { 
          "LDAPCfg_Search", ldap_cfg_search_cmd,
          NULL, RSRC_CONF | ACCESS_CONF, TAKE2, 
          "Search LDAP Directory for Entries"
     },

     { 
          "LDAPCfg_Load", ldap_cfg_load_cmd,
          NULL, RSRC_CONF | ACCESS_CONF, TAKE1, 
          "Search LDAP Directory for and Load Apache Configuration Entries"
     },

     // Other options

     { 
          "LDAPCfg_Debug", ldap_cfg_debug_cmd,
          NULL, RSRC_CONF | ACCESS_CONF, TAKE1, 
          "Numeric debug level"
     },
     { NULL }
};

module MODULE_VAR_EXPORT ldap_cfg_module = {
    STANDARD_MODULE_STUFF, 
    NULL,                         /* module initializer                  */
    NULL,                         /* create per-dir    config structures */
    NULL,                         /* merge  per-dir    config structures */
    ldap_cfg_create_srv_config,   /* create per-server config structures */
    ldap_cfg_merge_srv_config,    /* merge  per-server config structures */
    ldap_cfg_cmds,                /* table of config file commands       */
    NULL,                         /* [#8] MIME-typed-dispatched handlers */
    NULL,                         /* [#1] URI to filename translation    */
    NULL,                         /* [#4] validate user id from request  */
    NULL,                         /* [#5] check if the user is ok _here_ */
    NULL,                         /* [#3] check access by host address   */
    NULL,                         /* [#6] determine MIME type            */
    NULL,                         /* [#7] pre-run fixups                 */
    NULL,                         /* [#9] log a transaction              */
    NULL,                         /* [#2] header parser                  */
    NULL,                         /* child_init                          */
    NULL,                         /* child_exit                          */
    NULL                          /* [#0] post read-request              */
};
