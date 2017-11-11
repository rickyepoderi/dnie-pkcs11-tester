/*
 * Copyright (c) 2016 ricky <https://github.com/rickyepoderi/dnie-pkcs11-tester>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <termios.h>
#include <getopt.h>
#include <sys/wait.h>
#include <openssl/x509.h>
#include <dlfcn.h>

#define KWHT  "\x1B[37m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KNRM  "\x1B[0m"

/* TEST STRUCT */

typedef struct {
  char *name;
  char *description;
  unsigned char is_default;
  int (*test)(char *password);
} dnie_test;

/* GLOVAL VARS */

int slot = -1;
int use_cert_names = 1;
void* pkcs11_handle = NULL;
CK_C_Initialize C_Initialize_handle = NULL;
CK_C_Finalize C_Finalize_handle = NULL;
CK_C_GetFunctionList C_GetFunctionList_handle = NULL;

/* HELPER FUNCTIONS */

void error(int print_pid, const char *format, ...) {
  va_list arglist;
  printf("%s", KRED);
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)%s\n", getpid(), KNRM);
  } else {
    printf("%s\n", KNRM);
  }
}

void message(int print_pid, const char *format, ...) {
  va_list arglist;
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)\n", getpid());
  } else {
    printf("%s\n", KNRM);
  }
}

void information(int print_pid, const char *format, ...) {
  va_list arglist;
  printf("%s", KGRN);
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  if (print_pid) {
    printf(" (%d)%s\n", getpid(), KNRM);
  } else {
    printf("%s\n", KNRM);
  }
}

char* log_session_info_state(CK_STATE s) {
  switch(s) {
    case CKS_RO_PUBLIC_SESSION: return "CKS_RO_PUBLIC_SESSION";
    case CKS_RO_USER_FUNCTIONS: return "CKS_RO_USER_FUNCTIONS";
    case CKS_RW_PUBLIC_SESSION: return "CKS_RW_PUBLIC_SESSION";
    case CKS_RW_USER_FUNCTIONS: return "CKS_RW_USER_FUNCTIONS";
    case CKS_RW_SO_FUNCTIONS: return "CKS_RW_SO_FUNCTIONS";
    default: return "Unkown info state";
  }
}

char* log_pkcs11_error_name(CK_RV rv) {
  switch(rv) {
    case CKR_OK: return "CKR_OK";
    case CKR_CANCEL: return "CKR_CANCEL";
    case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT: return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
    case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
    case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
    case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
    default:
      return "Unknown CKR error";
  }
}

void CHECK_RV(CK_RV rv, const char* function) {
  if (rv != CKR_OK) { 
    error(0, "Error in %s [%s]\n", function, log_pkcs11_error_name(rv));
    exit(1);
  }
}

char* class_to_string(CK_OBJECT_CLASS class) {
  switch (class) {
    case CKO_DATA:
      return "data object";
    case CKO_CERTIFICATE:
      return "certificate";
    case CKO_PUBLIC_KEY:
      return "public key";
    case CKO_PRIVATE_KEY:
      return "private key";
    case CKO_SECRET_KEY:
      return "secret key";
    case CKO_HW_FEATURE:
      return "hardware feature";
    case CKO_DOMAIN_PARAMETERS:
      return "domain parameters";
    case CKO_VENDOR_DEFINED:
      return "vendor defined";
    default:
      return "unknown";
  }
}

void request_password(char* password, int password_len) {
  struct termios oflags, nflags;

  // disabling echo
  tcgetattr(fileno(stdin), &oflags);
  nflags = oflags;
  nflags.c_lflag &= ~ECHO;
  nflags.c_lflag |= ECHONL;

  if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
    error(0, "tcsetattr");
    exit(1);
  }

  printf("password: ");
  fgets(password, password_len, stdin);
  password[strlen(password) - 1] = 0;

  // restore terminal
  if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
    error(0, "tcsetattr");
    exit(1);
  }
}

void load_pkcs11(char* path) {
  void* pkcs11_handle = dlopen(path, RTLD_NOW);
  if (!pkcs11_handle) {
    error(0, "Invalid pkcs#11 library %s. Error: %s.", path, dlerror());
    exit(1);
  }

  C_Initialize_handle = (CK_C_Initialize) dlsym(pkcs11_handle, "C_Initialize");
  if (!C_Initialize_handle) {
    error(0, "Error loading C_Initialize function: %s", dlerror());
    exit(1);
  }

  C_Finalize_handle = (CK_C_Finalize) dlsym(pkcs11_handle, "C_Finalize");
  if (!C_Finalize_handle) {
    error(0, "Error loading C_Finalize function: %s", dlerror());
    exit(1);
  }

  C_GetFunctionList_handle = (CK_C_GetFunctionList) dlsym(pkcs11_handle, "C_GetFunctionList");
  if (!C_GetFunctionList_handle) {
    error(0, "Error loading C_GetFunctionList function: %s", dlerror());
    exit(1);
  }
}

/* TESTS */

int test_dnie_inserted(char *password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 0;
  CK_SLOT_INFO info_slot;
  CK_SLOT_ID slots[128];
  CK_TOKEN_INFO info_token;

  CHECK_RV(C_Initialize_handle(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList_handle(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, NULL_PTR, &num_slots), "C_GetSlotList");
  if (num_slots == 0) {
    error(0, "No slots available in the system");
    return 1;
  } else if (num_slots > 128) {
    error(0, "Too many slots, only 128 are managed");
    return 1;
  } else {
    message(0, "  Found %d slots...", num_slots);
  }
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  for (int i = 0; i < num_slots; i++) {
    CHECK_RV(functions->C_GetSlotInfo(slots[i], &info_slot), "C_GetSlotInfo");
    message(0, "  Found slot: %d - \"%s\"", i, info_slot.slotDescription);
    CHECK_RV(functions->C_GetTokenInfo(slots[i], &info_token), "C_GetTokenInfo");
    message(0, "  Found token: \"%s\"", info_token.label);
    if (strstr((char*) info_token.label, "(DNI electrónico)") != NULL) {
      slot = i;
      use_cert_names = 1;
      break;
    } else if (strstr((char*) info_token.label, "DNI electrónico") != NULL) {
      slot = i;
      use_cert_names = 0;
      break;
    }
  }
  C_Finalize_handle(NULL_PTR);
  if (slot != -1) {
      message(0, "  Found DNIe at slot %d", slot);
      return 0;
  } else {
      error(0, "No DNIe card found");
      return 1;
  }
}

int test_login(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_SESSION_INFO info_session;

  CHECK_RV(C_Initialize_handle(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList_handle(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize_handle(NULL_PTR);
  if (info_session.state != CKS_RW_USER_FUNCTIONS) {
    error(0, "Invalid session state");
    return 1;
  }
  return 0;
}

int test_logout(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_SESSION_INFO info_session;

  CHECK_RV(C_Initialize_handle(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList_handle(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");

  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_GetSessionInfo(session, &info_session), "C_GetSessionInfo");
  message(0, "  Session status: %s", log_session_info_state(info_session.state));
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");

  C_Finalize_handle(NULL_PTR);
  if (info_session.state != CKS_RW_USER_FUNCTIONS) {
    error(0, "Invalid session state");
    return 1;
  }
  return 0;
}

#define MAX_OBJECTS 128
#define MAX_BUFFER_SIZE 2048

int read_private_always_authenticate(CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
  CK_BBOOL always_auth = FALSE;
  CK_RV res;
  CK_ATTRIBUTE values[1] = {
    {CKA_ALWAYS_AUTHENTICATE, &always_auth, sizeof(CK_BBOOL)},
  };
  res = functions->C_GetAttributeValue(session, object, values, 1);
  if (res == CKR_ATTRIBUTE_TYPE_INVALID) {
    // the library does not understand CKA_ALWAYS_AUTHENTICATE => return 0
    return 0;
  }
  CHECK_RV(res, "C_GetAttributeValue");
  return always_auth;
}

int read_certificate_value(CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
    CK_BYTE* buffer, CK_ULONG_PTR buffer_len) {
  CK_ATTRIBUTE values[1] = {
    {CKA_VALUE, buffer, *buffer_len},
  };
  X509 *x509;
  BIO *o = BIO_new_fp(stdout,BIO_NOCLOSE);

  CHECK_RV(functions->C_GetAttributeValue(session, object, values, 1), "C_GetAttributeValue");
  *buffer_len = values[0].ulValueLen;
  x509 = d2i_X509(NULL, (const unsigned char**) &buffer, (long int) buffer_len);
  if (x509 == NULL) {
    error(0, "Cannot allocate X509 certificate");
    return 1;
  }
  X509_print_ex(o, x509, XN_FLAG_COMPAT, X509_FLAG_COMPAT);
  X509_free(x509);
  return 0;
}

int test_objects(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_BBOOL bool_true = TRUE;
  CK_ATTRIBUTE template[1] = {
    {CKA_TOKEN, &bool_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_OBJECT_CLASS class;
  char buffer[MAX_BUFFER_SIZE + 1];
  CK_ATTRIBUTE values[2] = {
    {CKA_LABEL, buffer, MAX_BUFFER_SIZE},
    {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
  };
  CK_BYTE certificate[MAX_BUFFER_SIZE];
  CK_ULONG certificate_len = MAX_BUFFER_SIZE;
  int i;
  int found_auth_priv = 0, found_sign_priv = 0, found_auth_pub = 0, found_sign_pub = 0,
    found_auth_cert = 0, found_sign_cert = 0;

  CHECK_RV(C_Initialize_handle(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList_handle(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");
  CHECK_RV(functions->C_FindObjectsInit(session, template, sizeof(template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  message(0, "  Found %d objects in the DNIe", num_objects);
  for (i = 0; i < num_objects; i++) {
    values[0].ulValueLen = MAX_BUFFER_SIZE;
    CHECK_RV(functions->C_GetAttributeValue(session, vector_object[i], values, 2), "C_GetAttributeValue");
    ((char*)values[0].pValue)[values[0].ulValueLen] = '\0';
    message(0, "  %d.- %x: %s, %s", i, vector_object[i], (char*)values[0].pValue, 
      class_to_string(*((CK_OBJECT_CLASS*) values[1].pValue)));
    if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PRIVATE_KEY &&
        strcmp("KprivAutenticacion", (char*)values[0].pValue) == 0) {
      message(0, "  Found the authentication private key CKA_ALWAYS_AUTHENTICATE=%d",
        read_private_always_authenticate(functions, session, vector_object[i]));
      found_auth_priv = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PRIVATE_KEY &&
        strcmp("KprivFirmaDigital", (char*)values[0].pValue) == 0) {
      message(0, "  Found the signing private key CKA_ALWAYS_AUTHENTICATE=%d",
        read_private_always_authenticate(functions, session, vector_object[i]));
      found_sign_priv = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PUBLIC_KEY &&
        (strcmp("CertAutenticacion", (char*)values[0].pValue) == 0 ||
         strcmp("KpuAutenticacion", (char*)values[0].pValue) == 0)) {
      message(0, "  Found the authentication public key");
      found_auth_pub = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_PUBLIC_KEY &&
        (strcmp("CertFirmaDigital", (char*)values[0].pValue) == 0 ||
         strcmp("KpuFirmaDigital", (char*)values[0].pValue) == 0)) {
      message(0, "  Found the signing public key");
      found_sign_pub = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_CERTIFICATE &&
        strcmp("CertAutenticacion", (char*)values[0].pValue) == 0) {
      message(0, "  Found the authentication certificate");
      read_certificate_value(functions, session, vector_object[i], certificate, &certificate_len);
      found_auth_cert = 1;
    } else if (*((CK_OBJECT_CLASS*) values[1].pValue) == CKO_CERTIFICATE &&
        strcmp("CertFirmaDigital", (char*)values[0].pValue) == 0) {
      message(0, "  Found the signing certificate");
      read_certificate_value(functions, session, vector_object[i], certificate, &certificate_len);
      found_sign_cert = 1;
    }
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize_handle(NULL_PTR);
  if (!found_sign_priv || !found_sign_pub || !found_sign_cert ||
    !found_auth_priv || !found_auth_pub || !found_auth_cert) {
    error(0, "Some object is not found in the DNIe");
    return 1;
  }
  return 0;
}

int test_sign_internal(char* password, int times, char* priv_label, char* pub_label,
    unsigned int sleep_start, unsigned int sleep_sign, int print_pid) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  char* data = "something to sign";
  CK_BYTE signature[MAX_BUFFER_SIZE];
  CK_ULONG signature_len = MAX_BUFFER_SIZE;
  CK_BBOOL bool_true = TRUE;
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE sign_template[3] = {
    {CKA_TOKEN, &bool_true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &priv_class, sizeof(priv_class)},
    {CKA_LABEL, priv_label, strlen(priv_label)},
  };
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE ver_template[3] = {
    {CKA_TOKEN, &bool_true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &pub_class, sizeof(pub_class)},
    {CKA_LABEL, pub_label, strlen(pub_label)},
  };
  int ok = 0;
  int always_auth_key = -1;

  message(print_pid, "  Starting test_sign with %s...", priv_label);
  if (sleep_start > 0) {
    message(print_pid, "  Sleeping %d seconds before login and sign process", sleep_start);
    sleep(sleep_start);
    message(print_pid, "  Starting the login and sign process");
  }

  CHECK_RV(C_Initialize_handle(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList_handle(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");

  if (sleep_sign > 0) {
    message(print_pid, "  Sleeping %d seconds after login and before sign process", sleep_sign);
    sleep(sleep_sign);
    message(print_pid, "  Starting the sign process");
  }

  for (int i = 0; i < times; i++) {
    CHECK_RV(functions->C_FindObjectsInit(session, sign_template, sizeof(sign_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
    CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");

    if (num_objects == 1) {
      if (always_auth_key == -1) {
        always_auth_key = read_private_always_authenticate(functions, session, vector_object[0]);
      }
      if (always_auth_key && i > 0) {
        message(print_pid, "  Login again cos the key is CKA_ALWAYS_AUTHENTICATE");
        CHECK_RV(functions->C_Logout(session), "C_Logout");
        CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");
      }
      CHECK_RV(functions->C_SignInit(session, &mechanism, vector_object[0]), "C_SignInit");
      CHECK_RV(functions->C_Sign(session, (unsigned char*) data, strlen(data) + 1, signature, &signature_len), "C_Sign");
      message(print_pid, "  Signature %d done successfully", i + 1);
    } else {
      error(print_pid, "No private key found");
    }
    CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");

    CHECK_RV(functions->C_FindObjectsInit(session, ver_template, sizeof(ver_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
    CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
    if (num_objects == 1) {
      CHECK_RV(functions->C_VerifyInit(session, &mechanism, vector_object[0]), "C_VerifySignInit");
      CHECK_RV(functions->C_Verify(session, (unsigned char*) data, strlen(data) + 1, signature, signature_len), "C_Verify");
      message(print_pid, "  Verification %d done successfully", i + 1);
      ok = 1;
    } else {
      error(print_pid, "No public key found");
    }
    CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
  }

  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize_handle(NULL_PTR);
  if (!ok) {
    return 1;
  }
  return 0;
}

int test_sign(char* password, int times) {
  return test_sign_internal(password, times, 
    "KprivFirmaDigital", use_cert_names? "CertFirmaDigital" : "KpuFirmaDigital", 
    0, 0, 0);
}

int test_auth(char* password, int times) {
  return test_sign_internal(password, times, 
    "KprivAutenticacion", use_cert_names? "CertAutenticacion" : "KpuAutenticacion", 
    0, 0, 0);
}

int test_sign_two(char* password) {
  return test_sign(password, 2);
}

int test_auth_two(char* password) {
  return test_auth(password, 2);
}

int test_auth_eleven(char* password) {
  return test_auth(password, 11);
}

/* No DNIe object can encrypt/decrypt
int read_auth_certificate(CK_FUNCTION_LIST_PTR functions, CK_SESSION_HANDLE session, CK_BYTE* buffer, CK_ULONG_PTR buffer_len) {
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_BBOOL true = TRUE;
  CK_OBJECT_CLASS pub_class = CKO_CERTIFICATE;
  CK_CHAR pub_label[] = "CertAutenticacion";
  CK_ATTRIBUTE enc_template[3] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &pub_class, sizeof(pub_class)},
    {CKA_LABEL, pub_label, strlen(pub_label)},
  };
  CK_ATTRIBUTE values[1] = {
    {CKA_VALUE, buffer, *buffer_len},
  };

  CHECK_RV(functions->C_FindObjectsInit(session, enc_template, sizeof(enc_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  if (num_objects == 1) {
    CHECK_RV(functions->C_GetAttributeValue(session, vector_object[0], values, 1), "C_GetAttributeValue");
    *buffer_len = values[0].ulValueLen;
    message(0, "  The certificate was read successfully");
  } else {
    error(0, "No certificate found");
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");
}

int test_encrypt(char* password) {
  CK_FUNCTION_LIST_PTR functions;
  CK_ULONG num_slots = 128;
  CK_SLOT_ID slots[128];
  CK_SESSION_HANDLE session;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  char* data = "something to encrypt";
  CK_BYTE encrypted[MAX_BUFFER_SIZE];
  CK_ULONG encrypted_len = MAX_BUFFER_SIZE;
  CK_BYTE certificate[MAX_BUFFER_SIZE];
  CK_ULONG certificate_len = MAX_BUFFER_SIZE;
  X509 *x509;
  EVP_PKEY *pkey;
  RSA *cert_rsa_key;
  unsigned char *p;
  CK_BBOOL true = TRUE;
  CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
  CK_CHAR priv_label[] = "KprivAutenticacion";
  CK_ATTRIBUTE dec_template[] = {
    {CKA_TOKEN, &true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &priv_class, sizeof(priv_class)},
    {CKA_LABEL, priv_label, strlen(priv_label)},
  };
  CK_ULONG num_objects = MAX_OBJECTS;
  CK_OBJECT_HANDLE vector_object[MAX_OBJECTS];
  CK_BYTE decrypted[MAX_BUFFER_SIZE];
  CK_ULONG decrypted_len;

  information(0, "Starting test_encrypt...");
  CHECK_RV(C_Initialize(NULL_PTR), "C_Initialize");
  CHECK_RV(C_GetFunctionList(&functions), "C_GetFunctionList");
  CHECK_RV(functions->C_GetSlotList(TRUE, slots, &num_slots), "C_GetSlotList");
  CHECK_RV(functions->C_OpenSession(slots[slot], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, (CK_NOTIFY) NULL_PTR, &session), "C_OpenSession");
  CHECK_RV(functions->C_Login(session, CKU_USER, (unsigned char*) password, strlen(password)), "C_Login");

  read_auth_certificate(functions, session, certificate, &certificate_len);
  p = certificate;
  x509 = d2i_X509(NULL, &p, certificate_len);
  pkey = X509_get_pubkey(x509);
  cert_rsa_key = EVP_PKEY_get1_RSA(pkey);
  encrypted_len = RSA_public_encrypt(strlen(data) + 1, data, encrypted, cert_rsa_key, RSA_PKCS1_PADDING);
   
  RSA_free(cert_rsa_key);
  EVP_PKEY_free(pkey);
  X509_free(x509);

  CHECK_RV(functions->C_FindObjectsInit(session, dec_template, sizeof(dec_template)/sizeof(CK_ATTRIBUTE)), "C_FindObjectsInit");
  CHECK_RV(functions->C_FindObjects(session, vector_object, MAX_OBJECTS, &num_objects), "C_FindObjects");
  if (num_objects == 1) {
    CHECK_RV(functions->C_DecryptInit(session, &mechanism, vector_object[0]), "C_DecryptInit");
    CHECK_RV(functions->C_Decrypt(session, encrypted, encrypted_len, decrypted, &decrypted_len), "C_Decrypt");
    message(0, "  Decryption done successfully");
  } else {
    error(0, "No public key found");
  }
  CHECK_RV(functions->C_FindObjectsFinal(session), "C_FindObjectsFinal");

  CHECK_RV(functions->C_Logout(session), "C_Logout");
  CHECK_RV(functions->C_CloseSession(session), "C_CloseSession");
  C_Finalize(NULL_PTR);
}
*/

int test_process_interference(char* password) {
  int return_status;
  int pid;

  pid = fork();
  if (pid == 0) {
    // child starts immediately but waits between login and sign
    exit(test_sign_internal(password, 1, "KprivAutenticacion", 
      use_cert_names? "CertAutenticacion" : "KpuAutenticacion", 0, 60, 1));
  } else {
    // parent sleeps before start and then steals the session to the parent
    test_sign_internal(password, 1, "KprivAutenticacion", 
      use_cert_names? "CertAutenticacion" : "KpuAutenticacion", 30, 0, 1);
  }
  // only parent gets here
  waitpid(pid, &return_status, 0);
  return return_status;
}

/* DEFINED TESTS */

dnie_test tests[] = {
  {
    .name = "inserted",
    .description = "Looks for the DNIe being inserted. This test is compulsory and cannot be selected.",
    .test = test_dnie_inserted,
    .is_default = 1,
  },
  {
    .name = "login",
    .description = "Login into the DNIe.",
    .test = test_login,
    .is_default = 1,
  },
  {
    .name = "list-objects",
    .description = "List all objects inside the DNIe.",
    .test = test_objects,
    .is_default = 1,
  },
  {
    .name = "logout",
    .description = "Test for login, logout and login again.",
    .test = test_logout,
    .is_default = 1,
  },
  {
    .name = "signature",
    .description = "Performs two sequential signatures with the sign key.",
    .test = test_sign_two,
    .is_default = 1,
  },
  {
    .name = "authentication",
    .description = "Performs two sequential signatures with the auth key.",
    .test = test_auth_two,
    .is_default = 1,
  },
  {
    .name = "interference",
    .description = "Executes two processes in that way that one steals the secure channel of the other after the login, some sleeps are used for that, this test is 60 seconds in length.",
    .test = test_process_interference,
    .is_default = 1,
  },
  {
    .name = "auth-11",
    .description = "Executes 11 signatures with the auth key. OpenSC has a default pin cache of 10 uses, DNIe v3.0 needs more.",
    .test = test_auth_eleven,
    .is_default = 0,
  }
};

/* USAGE */

void usage(const char* format, ...) {
  va_list arglist;

  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  printf("%s\n", KNRM);
  message(0, "");
  message(0, "  Usage: dnie-pkcs11-tester [OPTIONS] pkcs11-lib.so");
  message(0, "");
  message(0, "  ARGUMENTS:");
  message(0, "    pkcs11-lib.so: PKCS#11 library to test.");
  message(0, "");
  message(0, "  OPTIONS:");
  message(0, "    --test=TEST -t TEST: Executes the test TEST (order or name of the test).");
  message(0, "      This parameter can be used several times (several tests are run).");
  message(0, "    --all -a: All default tests are executed.");
  message(0, "    --help -h: Prints this usage.");
  message(0, "");
  message(0, "  TESTS:");
  for (int i = 1; i < sizeof(tests) / sizeof(dnie_test); i++) {
    message(0, "    %2d.- name: %s", i, tests[i].name);
    message(0, "         description: %s", tests[i].description);
    message(0, "         default: %s", tests[i].is_default? "yes":"no");
  }
  exit(1);
}

/* MAIN */

void search_for_test(unsigned char* tests_run, char* name) {
  char *tmp;
  int idx = strtol(name, &tmp, 10);
  if (*tmp == '\0' && idx > 0 && idx < sizeof(tests) / sizeof(dnie_test)) {
    // the test is specified using an index
    tests_run[idx] = 1;
    return;
  } else {
    // search using the name of the test
    for (int idx = 1; idx < sizeof(tests) / sizeof(dnie_test); idx++) {
      if (strncmp(tests[idx].name, name, strlen(tests[idx].name)+1) == 0) {
        tests_run[idx] = 1;
        return;
      }
    }
  }
  usage("invalid test '%s' specified", name);
}

int run_test(dnie_test* test, char* password) {
  int rc;
  information(0, "Starting test %s...", test->name);
  rc = test->test(password);
  if (rc == 0) {
    information(0, "Test %s executed OK", test->name);
  } else {
    error(0, "Test %s KO", test->name);
  }
  return rc;
}

#define RUN_CHECK(rv) if (rv != 0) return 1

int main(int argc, char *argv[]) {
  char password[128];
  unsigned char tests_run[sizeof(tests) / sizeof(dnie_test)];
  int c, all_flag = 0;
  static struct option long_options[] = {
    {"test", required_argument, 0, 't'},
    {"all", no_argument, 0, 'a'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  while ((c = getopt_long(argc, argv, "aht:", long_options, NULL)) != -1) {
    switch (c) {
      case 'a': all_flag = 1; break;
      case 't': search_for_test(tests_run, optarg); break;
      case 'h':
      case '?': usage("");
    }
  }

  if (optind + 1 != argc) {
      usage("Invalid number of arguments. Only the PKCS#11 library is needed.");
  }
  load_pkcs11(argv[optind]);

  request_password(password, 128);
  for (int i = 0; i < sizeof(tests) / sizeof(dnie_test); i++) {
    if (i == 0 || tests_run[i] || (all_flag && tests[i].is_default)) {
      RUN_CHECK(run_test(&tests[i], password));
    }
  }
}
