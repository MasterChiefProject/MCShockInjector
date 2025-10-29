#include "memory.h"
#include "shellcode_manager.hpp"
#include "utils.hpp"

int main() {
	//1. First we detect that VALORANT-Win64-Shipping.exe is running.

	//2. We find the the address of the 180KB RWX region we implanted inside valorant.

	//3. We write to it the shellcode which loads our mod menu.

	//4. We execute the shellcode.

	//5. We check that mod menu loaded correctly.
}