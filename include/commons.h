/**
 * @file commons.h
 *
 * @author Boaz Lavon
 * @date 10/21
 */
#ifndef __COMMONS_H__
#define __COMMONS_H__

typedef enum result_e : int {

  RESULT_SUCESS = 0,
  ERROR_UNKNOWN,
  ERROR_INPUT_PARAMS,
  ERROR_OPEN_FILE,

  MAX_ERORR_CODE = 0xff
} result_t;


#endif /* __COMMONS_H__ */
