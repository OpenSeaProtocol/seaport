// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { OrderType, ItemType } from "./ConsiderationEnums.sol";

import {
    OrderParameters,
    Order,
    AdvancedOrder,
    OrderComponents,
    OrderStatus,
    CriteriaResolver,
    OfferItem,
    ConsiderationItem,
    SpentItem,
    ReceivedItem
} from "./ConsiderationStructs.sol";

import "./ConsiderationErrors.sol";

import { Executor } from "./Executor.sol";

import { ZoneInteraction } from "./ZoneInteraction.sol";

import {
    ContractOffererInterface
} from "../interfaces/ContractOffererInterface.sol";

/**
 * @title OrderValidator
 * @author 0age
 * @notice OrderValidator contains functionality related to validating orders
 *         and updating their status.
 */
contract OrderValidator is Executor, ZoneInteraction {
    // Track status of each order (validated, cancelled, and fraction filled).
    mapping(bytes32 => OrderStatus) private _orderStatus;

    mapping(address => uint256) internal _contractNonces;

    /**
     * @dev Derive and set hashes, reference chainId, and associated domain
     *      separator during deployment.
     *
     * @param conduitController A contract that deploys conduits, or proxies
     *                          that may optionally be used to transfer approved
     *                          ERC20/721/1155 tokens.
     */
    constructor(address conduitController) Executor(conduitController) {}

    /**
     * @dev Internal function to verify and update the status of a basic order.
     *
     * @param orderHash The hash of the order.
     * @param offerer   The offerer of the order.
     * @param signature A signature from the offerer indicating that the order
     *                  has been approved.
     */
    function _validateBasicOrderAndUpdateStatus(
        bytes32 orderHash,
        address offerer,
        bytes memory signature
    ) internal {
        // Retrieve the order status for the given order hash.
        OrderStatus storage orderStatus = _orderStatus[orderHash];

        // Ensure order is fillable and is not cancelled.
        _verifyOrderStatus(
            orderHash,
            orderStatus,
            true, // Only allow unused orders when fulfilling basic orders.
            true // Signifies to revert if the order is invalid.
        );

        // If the order is not already validated, verify the supplied signature.
        if (!orderStatus.isValidated) {
            _verifySignature(offerer, orderHash, signature);
        }

        // Update order status as fully filled, packing struct values.
        orderStatus.isValidated = true;
        orderStatus.isCancelled = false;
        orderStatus.numerator = 1;
        orderStatus.denominator = 1;
    }

    /**
     * @dev Internal function to validate an order, determine what portion to
     *      fill, and update its status. The desired fill amount is supplied as
     *      a fraction, as is the returned amount to fill.
     *
     * @param advancedOrder     The order to fulfill as well as the fraction to
     *                          fill. Note that all offer and consideration
     *                          amounts must divide with no remainder in order
     *                          for a partial fill to be valid.
     * @param criteriaResolvers An array where each element contains a reference
     *                          to a specific offer or consideration, a token
     *                          identifier, and a proof that the supplied token
     *                          identifier is contained in the order's merkle
     *                          root. Note that a criteria of zero indicates
     *                          that any (transferable) token identifier is
     *                          valid and that no proof needs to be supplied.
     * @param revertOnInvalid   A boolean indicating whether to revert if the
     *                          order is invalid due to the time or status.
     * @param priorOrderHashes  The order hashes of each order supplied prior to
     *                          the current order as part of a "match" variety
     *                          of order fulfillment (e.g. this array will be
     *                          empty for single or "fulfill available").
     *
     * @return orderHash      The order hash.
     * @return newNumerator   A value indicating the portion of the order that
     *                        will be filled.
     * @return newDenominator A value indicating the total size of the order.
     */
    function _validateOrderAndUpdateStatus(
        AdvancedOrder memory advancedOrder,
        CriteriaResolver[] memory criteriaResolvers,
        bool revertOnInvalid,
        bytes32[] memory priorOrderHashes
    )
        internal
        returns (
            bytes32 orderHash,
            uint256 newNumerator,
            uint256 newDenominator
        )
    {
        // Retrieve the parameters for the order.
        OrderParameters memory orderParameters = advancedOrder.parameters;

        // Ensure current timestamp falls between order start time and end time.
        if (
            !_verifyTime(
                orderParameters.startTime,
                orderParameters.endTime,
                revertOnInvalid
            )
        ) {
            // Assuming an invalid time and no revert, return zeroed out values.
            return (bytes32(0), 0, 0);
        }

        if (orderParameters.orderType == OrderType.CONTRACT) {
            return
                _getGeneratedOrder(
                    orderParameters,
                    advancedOrder.extraData,
                    revertOnInvalid
                );
        }

        // Read numerator and denominator from memory and place on the stack.
        uint256 numerator = uint256(advancedOrder.numerator);
        uint256 denominator = uint256(advancedOrder.denominator);

        // Ensure that the supplied numerator and denominator are valid.
        if (numerator > denominator || numerator == 0) {
            _revertBadFraction();
        }

        // If attempting partial fill (n < d) check order type & ensure support.
        if (
            numerator < denominator &&
            _doesNotSupportPartialFills(orderParameters.orderType)
        ) {
            // Revert if partial fill was attempted on an unsupported order.
            _revertPartialFillsNotEnabledForOrder();
        }

        // Retrieve current counter & use it w/ parameters to derive order hash.
        orderHash = _assertConsiderationLengthAndGetOrderHash(orderParameters);

        // Ensure restricted orders have a valid submitter or pass a zone check.
        _assertRestrictedAdvancedOrderValidity(
            advancedOrder,
            criteriaResolvers,
            priorOrderHashes,
            orderHash,
            orderParameters.zoneHash,
            orderParameters.orderType,
            orderParameters.offerer,
            orderParameters.zone
        );

        // Retrieve the order status using the derived order hash.
        OrderStatus storage orderStatus = _orderStatus[orderHash];

        // Ensure order is fillable and is not cancelled.
        if (
            !_verifyOrderStatus(
                orderHash,
                orderStatus,
                false, // Allow partially used orders to be filled.
                revertOnInvalid
            )
        ) {
            // Assuming an invalid order status and no revert, return zero fill.
            return (orderHash, 0, 0);
        }

        // If the order is not already validated, verify the supplied signature.
        if (!orderStatus.isValidated) {
            _verifySignature(
                orderParameters.offerer,
                orderHash,
                advancedOrder.signature
            );
        }

        // Read filled amount as numerator and denominator and put on the stack.
        uint256 filledNumerator = orderStatus.numerator;
        uint256 filledDenominator = orderStatus.denominator;

        // If order (orderStatus) currently has a non-zero denominator it is
        // partially filled.
        if (filledDenominator != 0) {
            // If denominator of 1 supplied, fill all remaining amount on order.
            if (denominator == 1) {
                // Scale numerator & denominator to match current denominator.
                numerator = filledDenominator;
                denominator = filledDenominator;
            }
            // Otherwise, if supplied denominator differs from current one...
            else if (filledDenominator != denominator) {
                // scale current numerator by the supplied denominator, then...
                filledNumerator *= denominator;

                // the supplied numerator & denominator by current denominator.
                numerator *= filledDenominator;
                denominator *= filledDenominator;
            }

            // Once adjusted, if current+supplied numerator exceeds denominator:
            if (filledNumerator + numerator > denominator) {
                // Skip underflow check: denominator >= orderStatus.numerator
                unchecked {
                    // Reduce current numerator so it + supplied = denominator.
                    numerator = denominator - filledNumerator;
                }
            }

            // Increment the filled numerator by the new numerator.
            filledNumerator += numerator;

            // Use assembly to ensure fractional amounts are below max uint120.
            assembly {
                // Check filledNumerator and denominator for uint120 overflow.
                if or(
                    gt(filledNumerator, MaxUint120),
                    gt(denominator, MaxUint120)
                ) {
                    // Derive greatest common divisor using euclidean algorithm.
                    function gcd(_a, _b) -> out {
                        for {

                        } _b {

                        } {
                            let _c := _b
                            _b := mod(_a, _c)
                            _a := _c
                        }
                        out := _a
                    }
                    let scaleDown := gcd(
                        numerator,
                        gcd(filledNumerator, denominator)
                    )

                    // Ensure that the divisor is at least one.
                    let safeScaleDown := add(scaleDown, iszero(scaleDown))

                    // Scale all fractional values down by gcd.
                    numerator := div(numerator, safeScaleDown)
                    filledNumerator := div(filledNumerator, safeScaleDown)
                    denominator := div(denominator, safeScaleDown)

                    // Perform the overflow check a second time.
                    if or(
                        gt(filledNumerator, MaxUint120),
                        gt(denominator, MaxUint120)
                    ) {
                        // Store the Panic error signature.
                        mstore(0, Panic_error_selector)
                        // Store the arithmetic (0x11) panic code.
                        mstore(Panic_error_code_ptr, Panic_arithmetic)
                        // revert(abi.encodeWithSignature("Panic(uint256)", 0x11))
                        revert(0x1c, Panic_error_length)
                    }
                }
            }
            // Skip overflow check: checked above unless numerator is reduced.
            unchecked {
                // Update order status and fill amount, packing struct values.
                orderStatus.isValidated = true;
                orderStatus.isCancelled = false;
                orderStatus.numerator = uint120(filledNumerator);
                orderStatus.denominator = uint120(denominator);
            }
        } else {
            // Update order status and fill amount, packing struct values.
            orderStatus.isValidated = true;
            orderStatus.isCancelled = false;
            orderStatus.numerator = uint120(numerator);
            orderStatus.denominator = uint120(denominator);
        }

        // Return order hash, a modified numerator, and a modified denominator.
        return (orderHash, numerator, denominator);
    }

    function _decodeContractOrderReturnData()
        internal
        pure
        returns (SpentItem[] memory offer, ReceivedItem[] memory consideration)
    {
        assembly {
            // First two words of calldata are the offsets to offer and consideration
            // array lengths. Copy these to scratch space.
            returndatacopy(0, 0, TwoWords)
            let offsetOffer := mload(0)
            let offsetConsideration := mload(0x20)

            // Copy length of offer array to scratch space
            returndatacopy(0, offsetOffer, 0x20)
            let offerLength := mload(0)
            // Copy length of consideration array to scratch space
            returndatacopy(0x20, offsetConsideration, 0x20)
            let considerationLength := mload(0x20)

            // Calculate total size of offer and consideration arrays
            let totalOfferSize := mul(SpentItem_size, offerLength)
            let totalConsiderationSize := mul(ReceivedItem_size, considerationLength)

            // Add 4 words to total size to cover the offset and length fields of
            // the two arrays
            let totalSize := add(
                FourWords,
                add(totalOfferSize, totalConsiderationSize)
            )
            // Revert if returndatasize exceeds 65535 bytes or returndatasize
            // is not equal to the calculated size.
            if or(
                gt(or(offerLength, considerationLength), 0xffff),
                xor(totalSize, returndatasize())
            ) {
                mstore(0, Panic_error_selector)
                mstore(Panic_error_code_ptr, Panic_resource)
                revert(0, Panic_error_length)
            }

            offer := mload(0x40)
            let mPtrTailOffer := writeArrayPointers(offer, offerLength, 0x80)
            returndatacopy(mPtrTailOffer, add(offsetOffer, 32), totalOfferSize)
            consideration := add(mPtrTailOffer, totalOfferSize)
            let mPtrTailConsideration := writeArrayPointers(
                consideration,
                considerationLength,
                0xa0
            )
            returndatacopy(
                mPtrTailConsideration,
                add(offsetConsideration, 32),
                totalConsiderationSize
            )
            mstore(FreeMemoryPointerSlot, add(mPtrTailConsideration, totalConsiderationSize))

            function writeArrayPointers(mPtrLength, length, memoryStride)
                -> mPtrTail
            {
                mstore(mPtrLength, length)
                let mPtrHead := add(mPtrLength, 0x20)
                let headSize := mul(length, 0x20)
                mPtrTail := add(mPtrHead, headSize)
                let mPtrTailNext := mPtrTail
                for {

                } lt(mPtrHead, mPtrTail) {

                } {
                    mstore(mPtrHead, mPtrTailNext)
                    mPtrHead := add(mPtrHead, 0x20)
                    mPtrTailNext := add(mPtrTailNext, memoryStride)
                }
            }
        }
    }

    function _getGeneratedOrder(
        OrderParameters memory orderParameters,
        bytes memory context,
        bool revertOnInvalid
    )
        internal
        returns (
            bytes32 orderHash,
            uint256 numerator,
            uint256 denominator
        )
    {
        bytes4 selector = ContractOffererInterface.generateOrder.selector;
        address offerer = orderParameters.offerer;
        bool success;
        assembly {
            let cdPtr := mload(0x40)
            mstore(cdPtr, selector)

            // Get the pointer to the offers array.
            let offerArrPtr := mload(
                add(orderParameters, OrderParameters_offer_head_offset)
            )
            let considerationArrPtr := mload(
                add(orderParameters, OrderParameters_consideration_head_offset)
            )

            let cdPtrHead := add(cdPtr, 4)
            let tailOffset := 0x60
            mstore(cdPtrHead, tailOffset)
            tailOffset := add(
                tailOffset,
                copySpentItemArray(offerArrPtr, add(cdPtrHead, tailOffset))
            )
            mstore(add(cdPtrHead, 0x20), tailOffset)
            tailOffset := add(
                tailOffset,
                copySpentItemArray(
                    considerationArrPtr,
                    add(cdPtrHead, tailOffset)
                )
            )
            mstore(add(cdPtrHead, 0x40), tailOffset)
            tailOffset := add(
                tailOffset,
                copyBytes(context, add(cdPtrHead, tailOffset))
            )

            success := call(gas(), offerer, 0, cdPtr, add(4, tailOffset), 0, 0)

            // Function to copy the itemType, token, identifier and amount from each
            // item in the offer or consideration arrays. Reused to minimize code duplication.
            function copySpentItemArray(mPtrLength, cdPtrLength) -> size {
                let length := mload(mPtrLength)
                mstore(cdPtrLength, length)

                // Get pointer to first item's head position in the array, containing
                // the item's pointer in memory. The head pointer will be incremented
                // until it reaches the tail position (start of the array data).
                let mPtrHead := add(mPtrLength, 0x20)
                // Position in memory to write next item for calldata. Since SpentItem
                // has a fixed length, the array elements do not contain head elements in
                // calldata, they are concatenated together after the array length.
                let cdPtrData := add(cdPtrLength, 0x20)
                // Pointer to end of array head in memory.
                let mPtrHeadEnd := add(mPtrHead, mul(length, 0x20))

                for {

                } lt(mPtrHead, mPtrHeadEnd) {

                } {
                    // Read pointer to data for the array element from its head position
                    let mPtrTail := mload(mPtrHead)
                    // Copy the itemType, token, identifier, amount from the item to calldata
                    mstore(cdPtrData, mload(mPtrTail))
                    mstore(
                        add(cdPtrData, Common_token_offset),
                        mload(add(mPtrTail, Common_token_offset))
                    )
                    mstore(
                        add(cdPtrData, Common_identifier_offset),
                        mload(add(mPtrTail, Common_identifier_offset))
                    )
                    mstore(
                        add(cdPtrData, Common_amount_offset),
                        mload(add(mPtrTail, Common_amount_offset))
                    )

                    mPtrHead := add(mPtrHead, 0x20)
                    cdPtrData := add(cdPtrData, SpentItem_size)
                }
                size := add(0x20, mul(length, SpentItem_size))
            }

            // Function to copy a `bytes` value from `mPtrLength` to `cdPtrLength`.
            function copyBytes(mPtrLength, cdPtrLength) -> size {
                let length := mload(mPtrLength)
                mstore(cdPtrLength, length)

                // Rounds the byte length up to the nearest multiple of 32 and adds one word
                // for the length.
                size := and(add(length, 63), 0xffffe0)

                // Get pointer to start of data
                let mPtrData := add(mPtrLength, 0x20)
                let cdPtrData := add(cdPtrLength, 0x20)
                let mPtrDataEnd := add(mPtrLength, size)

                // Copies one word at a time
                for {

                } lt(mPtrData, mPtrDataEnd) {

                } {
                    mstore(cdPtrData, mload(mPtrData))
                    mPtrData := add(mPtrData, 0x20)
                    cdPtrData := add(cdPtrData, 0x20)
                }
            }
        }
        if (!success) {
            if (!revertOnInvalid) {
                return (bytes32(0), 0, 0);
            }

            assembly {
                returndatacopy(0, 0, returndatasize())
                revert(0, returndatasize())
            }
        }
        (
            SpentItem[] memory offer,
            ReceivedItem[] memory consideration
        ) = _decodeContractOrderReturnData();

        uint256 errorBuffer = 0;

        {
            // Designate lengths.
            uint256 originalOfferLength = orderParameters.offer.length;
            uint256 newOfferLength = offer.length;

            // Explicitly specified offer items cannot be removed.
            if (originalOfferLength > newOfferLength) {
                return _revertOrReturnEmpty(revertOnInvalid);
            } else if (newOfferLength > originalOfferLength) {
                OfferItem[] memory extendedOffer = new OfferItem[](
                    newOfferLength
                );
                for (uint256 i = 0; i < originalOfferLength; ++i) {
                    extendedOffer[i] = orderParameters.offer[i];
                }
                orderParameters.offer = extendedOffer;
            }

            // Loop through offer and ensure at least as much on returned offer
            for (uint256 i = 0; i < originalOfferLength; ++i) {
                OfferItem memory originalOffer = orderParameters.offer[i];
                SpentItem memory newOffer = offer[i];

                errorBuffer = _check(
                    originalOffer,
                    newOffer,
                    originalOffer.endAmount,
                    newOffer.amount,
                    errorBuffer
                );
            }

            // add new offer items if there are more than original
            for (uint256 i = originalOfferLength; i < newOfferLength; ++i) {
                OfferItem memory originalOffer = orderParameters.offer[i];
                SpentItem memory newOffer = offer[i];

                originalOffer.itemType = newOffer.itemType;
                originalOffer.token = newOffer.token;
                originalOffer.identifierOrCriteria = newOffer.identifier;
                originalOffer.startAmount = newOffer.amount;
                originalOffer.endAmount = newOffer.amount;
            }
        }

        {
            // Declare virtual function pointer taking a ConsiderationItem and
            // ReceivedItem as its initial arguments.
            function(
                ConsiderationItem memory,
                ReceivedItem memory,
                uint256,
                uint256,
                uint256
            ) internal pure returns (uint256) _checkConsideration;

            {
                // Assign _check function to a new function pointer (it takes
                // an OfferItem + SpentItem as its initial arguments)
                function(
                    OfferItem memory,
                    SpentItem memory,
                    uint256,
                    uint256,
                    uint256
                ) internal pure returns (uint256) _checkOffer = _check;

                // Utilize assembly to override the virtual function pointer.
                assembly {
                    // Cast the function to the one with modified arguments.
                    _checkConsideration := _checkOffer
                }
            }

            // Designate lengths & memory locations.
            ConsiderationItem[] memory originalConsiderationArray = (
                orderParameters.consideration
            );
            uint256 originalConsiderationLength = originalConsiderationArray
                .length;
            uint256 newConsiderationLength = consideration.length;

            if (originalConsiderationLength != 0) {
                // Consideration items that are not explicitly specified cannot be
                // created. Note that this constraint could be relaxed if specified
                // consideration items can be split.
                if (newConsiderationLength > originalConsiderationLength) {
                    return _revertOrReturnEmpty(revertOnInvalid);
                }

                // Loop through returned consideration, ensure existing not exceeded
                for (uint256 i = 0; i < newConsiderationLength; ++i) {
                    ReceivedItem memory newConsideration = consideration[i];
                    ConsiderationItem memory originalConsideration = (
                        originalConsiderationArray[i]
                    );

                    errorBuffer = _checkConsideration(
                        originalConsideration,
                        newConsideration,
                        newConsideration.amount,
                        originalConsideration.endAmount,
                        errorBuffer
                    );

                    originalConsideration.recipient = newConsideration
                        .recipient;
                }

                // Shorten original consideration array if longer than new array.
                assembly {
                    mstore(originalConsiderationArray, newConsiderationLength)
                }
            } else {
                // TODO: optimize this
                orderParameters.consideration = new ConsiderationItem[](
                    newConsiderationLength
                );

                for (uint256 i = 0; i < newConsiderationLength; ++i) {
                    ReceivedItem memory newConsideration = consideration[i];
                    ConsiderationItem memory originalConsideration = (
                        orderParameters.consideration[i]
                    );

                    originalConsideration.itemType = newConsideration.itemType;
                    originalConsideration.token = newConsideration.token;
                    originalConsideration
                        .identifierOrCriteria = newConsideration.identifier;
                    originalConsideration.startAmount = newConsideration.amount;
                    originalConsideration.endAmount = newConsideration.amount;
                    originalConsideration.recipient = newConsideration
                        .recipient;
                }
            }
        }

        if (errorBuffer != 0) {
            return _revertOrReturnEmpty(revertOnInvalid);
        }

        // address offerer = orderParameters.offerer;
        uint256 contractNonce = _contractNonces[offerer]++;
        assembly {
            orderHash := or(contractNonce, shl(0x60, offerer))
        }
        return (orderHash, 1, 1);
    }

    function _check(
        OfferItem memory originalOffer,
        SpentItem memory newOffer,
        uint256 valueOne,
        uint256 valueTwo,
        uint256 errorBuffer
    ) internal pure returns (uint256 updatedErrorBuffer) {
        // Set returned identifier for criteria-based items with criteria = 0.
        if (
            (_cast(uint256(originalOffer.itemType) > 3) &
                _cast(originalOffer.identifierOrCriteria == 0)) != 0
        ) {
            originalOffer.itemType = _replaceCriteriaItemType(
                originalOffer.itemType
            );
            originalOffer.identifierOrCriteria = newOffer.identifier;
        }

        // Ensure the original and generated items are compatible.
        updatedErrorBuffer =
            errorBuffer |
            _cast(originalOffer.startAmount != originalOffer.endAmount) |
            _cast(valueOne > valueTwo) |
            _cast(originalOffer.itemType != newOffer.itemType) |
            _cast(originalOffer.token != newOffer.token) |
            _cast(originalOffer.identifierOrCriteria != newOffer.identifier);

        // Update the original amounts to use the generated amounts.
        originalOffer.startAmount = newOffer.amount;
        originalOffer.endAmount = newOffer.amount;
    }

    function _cast(bool b) internal pure returns (uint256 u) {
        assembly {
            u := b
        }
    }

    function _revertOrReturnEmpty(bool revertOnInvalid)
        internal
        pure
        returns (
            bytes32 orderHash,
            uint256 numerator,
            uint256 denominator
        )
    {
        if (!revertOnInvalid) {
            return (bytes32(0), 0, 0);
        }

        _revertNoSpecifiedOrdersAvailable(); // TODO: return a better error msg
    }

    function _replaceCriteriaItemType(ItemType originalItemType)
        internal
        pure
        returns (ItemType newItemType)
    {
        assembly {
            // Item type 4 becomes 2 and item type 5 becomes 3.
            newItemType := sub(3, eq(originalItemType, 4))
        }
    }

    /**
     * @dev Internal pure function to convert both offer and consideration items
     *      to spent items. Copied from reference contract for now.
     */
    function _convertToSpent(
        OfferItem[] memory offer,
        ConsiderationItem[] memory consideration,
        bytes memory context
    ) internal pure returns (bytes memory cdata) {
        bytes4 selector = ContractOffererInterface.generateOrder.selector;
        assembly {
            // Get free memory pointer to use for calldata to contract offerer
            cdata := mload(FreeMemoryPointerSlot)
            let cdPtr := add(cdata, 0x20)
            // Write function selector to memory
            mstore(cdPtr, selector)
            let cdPtrHead := add(cdPtr, 4)
            let tailOffset := GenerateOrder_tail_offset
            mstore(cdPtrHead, tailOffset)
            tailOffset := add(
                tailOffset,
                copySpentItemArray(offer, add(cdPtrHead, tailOffset))
            )
            mstore(add(cdPtrHead, 0x20), tailOffset)
            tailOffset := add(
                tailOffset,
                copySpentItemArray(consideration, add(cdPtrHead, tailOffset))
            )
            mstore(add(cdPtrHead, 0x40), tailOffset)
            tailOffset := add(
                tailOffset,
                copyBytes(context, add(cdPtrHead, tailOffset))
            )

            mstore(cdata, add(4, tailOffset))

            // Function to copy the itemType, token, identifier and amount from each
            // item in the offer or consideration arrays. Reused to minimize code duplication.
            function copySpentItemArray(mPtrLength, cdPtrLength) -> size {
                let length := mload(mPtrLength)
                mstore(cdPtrLength, length)

                // Get pointer to first item's head position in the array, containing
                // the item's pointer in memory. The head pointer will be incremented
                // until it reaches the tail position (start of the array data).
                let mPtrHead := add(mPtrLength, 0x20)
                // Position in memory to write next item for calldata. Since SpentItem
                // has a fixed length, the array elements do not contain head elements in
                // calldata, they are concatenated together after the array length.
                let cdPtrData := add(cdPtrLength, 0x20)
                // Pointer to end of array head in memory.
                let mPtrHeadEnd := add(mPtrHead, mul(length, 0x20))

                for {

                } lt(mPtrHead, mPtrHeadEnd) {

                } {
                    // Read pointer to data for the array element from its head position
                    let mPtrTail := mload(mPtrHead)
                    // Copy the itemType, token, identifier, amount from the item to calldata
                    mstore(cdPtrData, mload(mPtrTail))
                    mstore(
                        add(cdPtrData, Common_token_offset),
                        mload(add(mPtrTail, Common_token_offset))
                    )
                    mstore(
                        add(cdPtrData, Common_identifier_offset),
                        mload(add(mPtrTail, Common_identifier_offset))
                    )
                    mstore(
                        add(cdPtrData, Common_amount_offset),
                        mload(add(mPtrTail, Common_amount_offset))
                    )

                    mPtrHead := add(mPtrHead, 0x20)
                    cdPtrData := add(cdPtrData, SpentItem_size)
                }
                size := add(0x20, mul(length, SpentItem_size))
            }

            // Function to copy a `bytes` value from `mPtrLength` to `cdPtrLength`.
            function copyBytes(mPtrLength, cdPtrLength) -> size {
                let length := mload(mPtrLength)
                mstore(cdPtrLength, length)

                // Rounds the byte length up to the nearest multiple of 32 and adds one word
                // for the length.
                size := and(add(length, 63), 0xffffe0)

                // Get pointer to start of data
                let mPtrData := add(mPtrLength, 0x20)
                let cdPtrData := add(cdPtrLength, 0x20)
                let mPtrDataEnd := add(mPtrLength, size)

                // Copies one word at a time
                for {

                } lt(mPtrData, mPtrDataEnd) {

                } {
                    mstore(cdPtrData, mload(mPtrData))
                    mPtrData := add(mPtrData, 0x20)
                    cdPtrData := add(cdPtrData, 0x20)
                }
            }
        }
    }

    /**
     * @dev Internal function to cancel an arbitrary number of orders. Note that
     *      only the offerer or the zone of a given order may cancel it. Callers
     *      should ensure that the intended order was cancelled by calling
     *      `getOrderStatus` and confirming that `isCancelled` returns `true`.
     *
     * @param orders The orders to cancel.
     *
     * @return cancelled A boolean indicating whether the supplied orders were
     *                   successfully cancelled.
     */
    function _cancel(OrderComponents[] calldata orders)
        internal
        returns (bool cancelled)
    {
        // Ensure that the reentrancy guard is not currently set.
        _assertNonReentrant();

        // Declare variables outside of the loop.
        OrderStatus storage orderStatus;
        address offerer;
        address zone;

        // Skip overflow check as for loop is indexed starting at zero.
        unchecked {
            // Read length of the orders array from memory and place on stack.
            uint256 totalOrders = orders.length;

            // Iterate over each order.
            for (uint256 i = 0; i < totalOrders; ) {
                // Retrieve the order.
                OrderComponents calldata order = orders[i];

                offerer = order.offerer;
                zone = order.zone;

                // Ensure caller is either offerer or zone of the order.
                if (
                    !_unmaskedAddressComparison(msg.sender, offerer) &&
                    !_unmaskedAddressComparison(msg.sender, zone)
                ) {
                    _revertInvalidCanceller();
                }

                // Derive order hash using the order parameters and the counter.
                bytes32 orderHash = _deriveOrderHash(
                    OrderParameters(
                        offerer,
                        zone,
                        order.offer,
                        order.consideration,
                        order.orderType,
                        order.startTime,
                        order.endTime,
                        order.zoneHash,
                        order.salt,
                        order.conduitKey,
                        order.consideration.length
                    ),
                    order.counter
                );

                // Retrieve the order status using the derived order hash.
                orderStatus = _orderStatus[orderHash];

                // Update the order status as not valid and cancelled.
                orderStatus.isValidated = false;
                orderStatus.isCancelled = true;

                // Emit an event signifying that the order has been cancelled.
                emit OrderCancelled(orderHash, offerer, zone);

                // Increment counter inside body of loop for gas efficiency.
                ++i;
            }
        }

        // Return a boolean indicating that orders were successfully cancelled.
        cancelled = true;
    }

    /**
     * @dev Internal function to validate an arbitrary number of orders, thereby
     *      registering their signatures as valid and allowing the fulfiller to
     *      skip signature verification on fulfillment. Note that validated
     *      orders may still be unfulfillable due to invalid item amounts or
     *      other factors; callers should determine whether validated orders are
     *      fulfillable by simulating the fulfillment call prior to execution.
     *      Also note that anyone can validate a signed order, but only the
     *      offerer can validate an order without supplying a signature.
     *
     * @param orders The orders to validate.
     *
     * @return validated A boolean indicating whether the supplied orders were
     *                   successfully validated.
     */
    function _validate(Order[] calldata orders)
        internal
        returns (bool validated)
    {
        // Ensure that the reentrancy guard is not currently set.
        _assertNonReentrant();

        // Declare variables outside of the loop.
        OrderStatus storage orderStatus;
        bytes32 orderHash;
        address offerer;

        // Skip overflow check as for loop is indexed starting at zero.
        unchecked {
            // Read length of the orders array from memory and place on stack.
            uint256 totalOrders = orders.length;

            // Iterate over each order.
            for (uint256 i = 0; i < totalOrders; ) {
                // Retrieve the order.
                Order calldata order = orders[i];

                // Retrieve the order parameters.
                OrderParameters calldata orderParameters = order.parameters;

                // Move offerer from memory to the stack.
                offerer = orderParameters.offerer;

                // Get current counter & use it w/ params to derive order hash.
                orderHash = _assertConsiderationLengthAndGetOrderHash(
                    orderParameters
                );

                // Retrieve the order status using the derived order hash.
                orderStatus = _orderStatus[orderHash];

                // Ensure order is fillable and retrieve the filled amount.
                _verifyOrderStatus(
                    orderHash,
                    orderStatus,
                    false, // Signifies that partially filled orders are valid.
                    true // Signifies to revert if the order is invalid.
                );

                // If the order has not already been validated...
                if (!orderStatus.isValidated) {
                    // Verify the supplied signature.
                    _verifySignature(offerer, orderHash, order.signature);

                    // Update order status to mark the order as valid.
                    orderStatus.isValidated = true;

                    // Emit an event signifying the order has been validated.
                    emit OrderValidated(
                        orderHash,
                        offerer,
                        orderParameters.zone
                    );
                }

                // Increment counter inside body of the loop for gas efficiency.
                ++i;
            }
        }

        // Return a boolean indicating that orders were successfully validated.
        validated = true;
    }

    /**
     * @dev Internal view function to retrieve the status of a given order by
     *      hash, including whether the order has been cancelled or validated
     *      and the fraction of the order that has been filled.
     *
     * @param orderHash The order hash in question.
     *
     * @return isValidated A boolean indicating whether the order in question
     *                     has been validated (i.e. previously approved or
     *                     partially filled).
     * @return isCancelled A boolean indicating whether the order in question
     *                     has been cancelled.
     * @return totalFilled The total portion of the order that has been filled
     *                     (i.e. the "numerator").
     * @return totalSize   The total size of the order that is either filled or
     *                     unfilled (i.e. the "denominator").
     */
    function _getOrderStatus(bytes32 orderHash)
        internal
        view
        returns (
            bool isValidated,
            bool isCancelled,
            uint256 totalFilled,
            uint256 totalSize
        )
    {
        // Retrieve the order status using the order hash.
        OrderStatus storage orderStatus = _orderStatus[orderHash];

        // Return the fields on the order status.
        return (
            orderStatus.isValidated,
            orderStatus.isCancelled,
            orderStatus.numerator,
            orderStatus.denominator
        );
    }

    /**
     * @dev Internal pure function to check whether a given order type indicates
     *      that partial fills are not supported (e.g. only "full fills" are
     *      allowed for the order in question).
     *
     * @param orderType The order type in question.
     *
     * @return isFullOrder A boolean indicating whether the order type only
     *                     supports full fills.
     */
    function _doesNotSupportPartialFills(OrderType orderType)
        internal
        pure
        returns (bool isFullOrder)
    {
        // The "full" order types are even, while "partial" order types are odd.
        // Bitwise and by 1 is equivalent to modulo by 2, but 2 gas cheaper.
        assembly {
            // Equivalent to `uint256(orderType) & 1 == 0`.
            isFullOrder := iszero(and(orderType, 1))
        }
    }
}
