
// stub module to test header files' C++ compatibility

extern "C" {
  #include <njt_config.h>
  #include <njt_core.h>
  #include <njt_event.h>
  #include <njt_event_connect.h>
  #include <njt_event_pipe.h>

  #include <njt_http.h>

  #include <njt_mail.h>
  #include <njt_mail_pop3_module.h>
  #include <njt_mail_imap_module.h>
  #include <njt_mail_smtp_module.h>

  #include <njt_stream.h>
}

// njet header files should go before other, because they define 64-bit off_t
// #include <string>


void njt_cpp_test_handler(void *data);

void
njt_cpp_test_handler(void *data)
{
    return;
}
