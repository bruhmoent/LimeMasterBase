#include "base/masterbase.hpp"

int main() {
    MasterBase masterBase;
    masterBase.WaitForClientConnection();
    return 0;
}