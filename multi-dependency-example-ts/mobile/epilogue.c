/** @file
 * @brief Mobile Group
 *
 * mobile group epilogue.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#define TE_TEST_NAME    "mobile/epilogue"

#include "te_config.h"
#include "tapi_test.h"

int
main(int argc, char **argv)
{
    TEST_START;

    TEST_STEP("Finalize the mobile group");
    /*
     * Stand-in servers and changed server addresses are undone by each
     * test and by the Configurator rollback.
     */

    TEST_SUCCESS;

cleanup:

    TEST_END;
}
