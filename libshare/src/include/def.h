#ifndef __CWMP_DEF_H__
#define __CWMP_DEF_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define URL_HTTP_HDR    "http://"
#define URL_HTTPS_HDR   "https://"

#define URL_SIZE                (256)
#define USERNAME_SIZE           (256)
#define PASSWORD_SIZE           (256)
#define IFNAME_SIZE             (16)
#define IPADDR_SIZE             (64)
#define PORT_SIZE               (8)
#define HWADDR_SIZE             (20)
#define MANUFACTURER_SIZE       (64)
#define OUI_SIZE                (32)
#define PRODUCT_CLASS_SIZE      (32)
#define SERIAL_NUMBER_SIZE      (64)
#define HARDWARE_VERSION_SIZE   (32)
#define SOFTWARE_VERSION_SIZE   (32)
#define DEVICE_TYPE_SIZE        (32)
#define COOKIE_SIZE             (64)
#define PATHNAME_SIZE           (256)
#define COMMANDKEY_SIZE         (32)
#define FILETYPE_SIZE           (64)

#define PORT_MIN                (1)
#define PORT_MAX                (65535)

#define USLEEP_INTERVAL         (10)

#define RESEND_MAXCOUNT         (10)
#define DOWNLOAD_RETRYCOUNT_MAX (5)

#define INFORM_RETRY_MAXCOUNT   (10)
#define TRANSFER_COMPLETE_RETRY_MAXCOUNT    (5)

#define SEC2MSEC                (1000)
#define MSEC2USEC               (1000)
#define SEC2USEC                (1000 * 1000)
#define BYTE_TO_MBYTE           (1024*1024)

#ifndef BASE_DIR
#define BASE_DIR                "/etc/cwmp"
#endif
#ifndef TMP_DIR
#define TMP_DIR                 "/tmp"
#endif


#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_DEF_H__*/
