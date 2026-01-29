/*
 * ao-payments-stripe - Provider for Stripe.
 * Copyright (C) 2015, 2016, 2019, 2020, 2021, 2022, 2023, 2024, 2025  AO Industries, Inc.
 *     support@aoindustries.com
 *     7262 Bull Pen Cir
 *     Mobile, AL 36695
 *
 * This file is part of ao-payments-stripe.
 *
 * ao-payments-stripe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ao-payments-stripe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with ao-payments-stripe.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.aoapps.payments.stripe;

import static com.aoapps.payments.CreditCard.MASK_CHARACTER;
import static com.aoapps.payments.CreditCard.UNKNOWN_DIGIT;
import static com.aoapps.payments.CreditCard.UNKNOWN_MIDDLE;
import static com.aoapps.payments.Resources.PACKAGE_RESOURCES;

import com.aoapps.collections.AoCollections;
import com.aoapps.lang.io.LocalizedIOException;
import com.aoapps.lang.math.SafeMath;
import com.aoapps.payments.AuthorizationResult;
import com.aoapps.payments.CaptureResult;
import com.aoapps.payments.CreditCard;
import com.aoapps.payments.CreditResult;
import com.aoapps.payments.MerchantServicesProvider;
import com.aoapps.payments.SaleResult;
import com.aoapps.payments.TokenizedCreditCard;
import com.aoapps.payments.Transaction;
import com.aoapps.payments.TransactionRequest;
import com.aoapps.payments.TransactionResult;
import com.aoapps.payments.VoidResult;
import com.stripe.exception.ApiConnectionException;
import com.stripe.exception.ApiException;
import com.stripe.exception.AuthenticationException;
import com.stripe.exception.CardException;
import com.stripe.exception.EventDataObjectDeserializationException;
import com.stripe.exception.IdempotencyException;
import com.stripe.exception.InvalidRequestException;
import com.stripe.exception.PermissionException;
import com.stripe.exception.RateLimitException;
import com.stripe.exception.SignatureVerificationException;
import com.stripe.exception.StripeException;
import com.stripe.exception.oauth.OAuthException;
import com.stripe.model.Card;
import com.stripe.model.Charge;
import com.stripe.model.Customer;
import com.stripe.model.PaymentIntent;
import com.stripe.model.PaymentMethod;
import com.stripe.model.PaymentMethodCollection;
import com.stripe.model.PaymentSource;
import com.stripe.model.StripeError;
import com.stripe.model.oauth.OAuthError;
import com.stripe.net.RequestOptions;
import com.stripe.param.CardUpdateOnCustomerParams;
import com.stripe.param.CustomerCreateParams;
import com.stripe.param.CustomerListParams;
import com.stripe.param.CustomerRetrieveParams;
import com.stripe.param.CustomerUpdateParams;
import com.stripe.param.PaymentIntentCaptureParams;
import com.stripe.param.PaymentIntentCreateParams;
import com.stripe.param.PaymentMethodAttachParams;
import com.stripe.param.PaymentMethodCreateParams;
import com.stripe.param.PaymentMethodListParams;
import com.stripe.param.PaymentMethodUpdateParams;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.Currency;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Provider for Stripe.
 *
 * <p>Configuration parameters:</p>
 *
 * <ol>
 *   <li>apiKey - the Stripe account secret key</li>
 * </ol>
 *
 * <p>TODO: Support testMode with optional testApiKey.  This would require
 * testMode on CreditCard, too.</p>
 *
 * <p>TODO: Support Stripe.js</p>
 *
 * <p>TODO: Support Idempotent Requests with automatic retry on network errors.</p>
 *
 * <p>TODO: Support <a href="https://stripe.com/docs/api/request_ids?lang=java">Request IDs</a>.</p>
 *
 * <p>TODO: Support <a href="https://stripe.com/docs/connect/direct-charges#collecting-fees">Collecting application fees</a>?</p>
 *
 * <p>TODO: Can we get this listed as a <a href="https://stripe.com/docs/libraries#java">community library or plugin-in</a>?</p>
 *
 * <p>TODO: Might be better to switch to <a href="https://stripe.com/docs/billing/subscriptions/payment">Subscriptions</a> for stored card implementation.</p>
 *
 * @author  AO Industries, Inc.
 */
public class Stripe implements MerchantServicesProvider {

  private static final Logger logger = Logger.getLogger(Stripe.class.getName());

  /**
   * Configures performing updates through the map-based interface.  A future version of the underlying API may be able to
   * fully use the builder API.
   *
   * <p>Currently, with Stripe API version 12.1.0, there is no way to unset a value through the builder-pattern API.
   * Setting to {@code null} does not send any parameter.  Setting to {@code ""} results in the following error:</p>
   *
   * <blockquote>You cannot set 'description' to an empty string. We interpret empty strings as null in requests. You may set 'description' to null to delete the property.</blockquote>
   */
  private static final boolean UPDATE_WITH_MAP_API = true; // A future version of the Stripe API may allow this false, with removal of then-unused map-based code.

  /**
   * See <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>.
   */
  private static final int MAX_METADATA_KEYS = 50;

  /**
   * See <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>.
   */
  private static final int MAX_METADATA_KEY_LENGTH = 40;

  /**
   * See <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>.
   */
  private static final int MAX_METADATA_VALUE_LENGTH = 500;

  /**
   * The maximum allowed statement descriptor length.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/charges/create?lang=java">Create a charge</a>.</li>
   * <li>See <a href="https://stripe.com/docs/charges#dynamic-statement-descriptor">Dynamic statement descriptor</a>.</li>
   * </ol>
   */
  private static final int MAX_STATEMENT_DESCRIPTOR_LEN = 22;

  /**
   * The characters on the statement before the order number when the order number has no alpha characters itself.
   */
  // TODO: Make configurable in future version of API
  private static final String STATEMENT_DESCRIPTOR_PREFIX = "AO#";

  private final String providerId;
  private final String apiKey;

  private final RequestOptions options;

  /**
   * Creates a new String provider.
   */
  public Stripe(String providerId, String apiKey) {
    this.providerId = providerId;
    this.apiKey = apiKey;
    this.options = RequestOptions
        .builder()
        .setApiKey(apiKey)
        .build();
  }

  @Override
  public String getProviderId() {
    return providerId;
  }

  /**
   * Gets the API secret key.
   */
  public String getApiKey() {
    return apiKey;
  }

  /**
   * Adds a trimmed parameter to a map if the value is non-null and not empty after trimming.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   */
  private static void addParam(boolean update, Map<String, Object> params, String name, String value) {
    if (value != null) {
      value = value.trim();
      if (!value.isEmpty()) {
        params.put(name, value);
        return;
      }
    }
    if (update) {
      params.put(name, null);
    }
  }

  /**
   * Adds a parameter to a map if the value is non-null and not empty.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   */
  private static void addParam(boolean update, Map<String, Object> params, String name, Map<?, ?> map) {
    if (map != null && !map.isEmpty()) {
      params.put(name, map);
      return;
    }
    if (update) {
      params.put(name, null);
    }
  }

  /**
   * Adds a trimmed parameter to a map if the value is non-null and not empty after trimming.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   *
   * @return  {@code true} when the parameter was set, even if set to {@code null}.
   *          {@code false otherwise}.
   */
  @SuppressWarnings("overloads")
  private static boolean addParam(boolean update, Consumer<String> params, String value) {
    if (value != null) {
      value = value.trim();
      if (!value.isEmpty()) {
        params.accept(value);
        return true;
      }
    }
    if (update) {
      params.accept(null);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Adds a parameter to a map if the value is non-null.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   *
   * @return  {@code true} when the parameter was set, even if set to {@code null}.
   *          {@code false otherwise}.
   */
  @SuppressWarnings("overloads")
  private static <V> boolean addParam(boolean update, Consumer<V> params, V value) {
    if (value != null) {
      params.accept(value);
      return true;
    }
    if (update) {
      params.accept(null);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Adds a parameter to a map if the value is non-null and not empty.
   *
   * @param update  The parameter will always be added, (as empty map when {@code null}), to update an existing object
   *
   * @return  {@code true} when the parameter was set, even if set to an empty map for {@code null}.
   *          {@code false otherwise}.
   */
  @SuppressWarnings("overloads")
  private static <K, V> boolean addParam(boolean update, Consumer<Map<K, V>> params, Map<K, V> map) {
    if (map != null && !map.isEmpty()) {
      params.accept(map);
      return true;
    }
    if (update) {
      params.accept(Collections.emptyMap());
      return true;
    } else {
      return false;
    }
  }

  /**
   * Adds a trimmed metadata value if the value is non-null and not empty after trimming.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   * @param allowTruncate  Truncate the value if its length is greater than {@link Stripe#MAX_METADATA_VALUE_LENGTH},
   *                       rather than throwing {@link IllegalArgumentException}.
   *
   * @see  Stripe#addMetaData(boolean, java.util.Map, java.lang.String, java.lang.Object, boolean)
   */
  private static void addMetaData(boolean update, Map<String, String> metadata, String key, String value, boolean allowTruncate) {
    if (key.length() > MAX_METADATA_KEY_LENGTH) {
      throw new IllegalArgumentException("Meta data key too long: " + key);
    }
    if (value != null) {
      value = value.trim();
      if (!value.isEmpty()) {
        if (value.length() > MAX_METADATA_VALUE_LENGTH) {
          if (allowTruncate) {
            value = value.substring(0, MAX_METADATA_VALUE_LENGTH);
          } else {
            throw new IllegalArgumentException("Meta data value too long: " + value);
          }
        }
        if (!metadata.containsKey(key) && metadata.size() >= MAX_METADATA_KEYS) {
          throw new IllegalStateException("Too many meta data keys");
        }
        metadata.put(key, value);
        return;
      }
    }
    if (update) {
      metadata.put(key, null);
    }
  }

  /**
   * Adds a trimmed metadata value, via {@link Object#toString()}, if the value is non-null and not empty after trimming.
   *
   * @param update  The parameter will always be added, even if null, to update an existing object
   * @param allowTruncate  Truncate the value if its length is greater than {@link Stripe#MAX_METADATA_VALUE_LENGTH},
   *                       rather than throwing {@link IllegalArgumentException}.
   *
   * @see  Stripe#addMetaData(boolean, java.util.Map, java.lang.String, java.lang.String, boolean)
   */
  private static void addMetaData(boolean update, Map<String, String> metadata, String key, Object value, boolean allowTrimValue) {
    addMetaData(
        update,
        metadata,
        key,
        value == null ? (String) value : value.toString(),
        allowTrimValue
    );
  }

  /**
   * Creates the meta data for a customer.
   *
   * <p>See <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>.</p>
   *
   * <p>TODO: Review: <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>: "Do not store any sensitive information"</p>
   *
   * @param update  The parameters will always be added, even if null, to update an existing object
   */
  private static Map<String, String> makeCustomerMetadata(CreditCard creditCard, boolean update) {
    Map<String, String> metadata = new LinkedHashMap<>();
    addMetaData(update, metadata, "company_name", creditCard.getCompanyName(), true);
    addMetaData(update, metadata, "phone", null, true); // Moved to customer
    addMetaData(update, metadata, "fax", creditCard.getFax(), true);
    addMetaData(update, metadata, "customer_id", creditCard.getCustomerId(), true);
    addMetaData(update, metadata, "customer_tax_id", creditCard.getCustomerTaxId(), true);
    // TODO: In a future release, create only one customer per group?
    // TODO: Would also have to set the default based on our settings of which is selected for auto payment?
    addMetaData(update, metadata, "group_name", creditCard.getGroupName(), true); // TODO: Other connectors, too
    addMetaData(update, metadata, "principal_name", creditCard.getPrincipalName(), true); // TODO: Other connectors, too
    return metadata;
  }

  /**
   * Creates the meta data for both card meta data (also associated with "customer" for stored cards) and transaction meta data.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/charges/create?lang=java">Create a charge</a>.</li>
   * </ol>
   *
   * <p>TODO: Review: <a href="https://stripe.com/docs/api/metadata?lang=java">Metadata</a>: "Do not store any sensitive information"</p>
   */
  private static Map<String, String> makePaymentIntentMetadata(TransactionRequest transactionRequest, CreditCard creditCard, boolean update) {
    Map<String, String> metadata = makeCustomerMetadata(creditCard, update);
    // Additional customer meta data
    addMetaData(update, metadata, "customer_description", creditCard.getComments(), true);
    addMetaData(update, metadata, "customer_email", creditCard.getEmail(), false); // TODO: Email is other places, worth having here?
    // Transaction meta data
    addMetaData(update, metadata, "customer_ip", transactionRequest.getCustomerIp(), false);
    addMetaData(update, metadata, "order_number", transactionRequest.getOrderNumber(), false); // TODO: statement_descriptor only?
    addMetaData(update, metadata, "amount", transactionRequest.getAmount(), false);
    addMetaData(update, metadata, "tax_amount", transactionRequest.getTaxAmount(), false);
    addMetaData(update, metadata, "tax_exempt", transactionRequest.getTaxExempt(), false); // TODO: Move to "tax_exempt" found elsewhere?  Set on customer, too, once known here?
    addMetaData(update, metadata, "shipping_amount", transactionRequest.getShippingAmount(), false);
    addMetaData(update, metadata, "duty_amount", transactionRequest.getDutyAmount(), false);
    addMetaData(update, metadata, "shipping_company_name", transactionRequest.getShippingCompanyName(), true);
    addMetaData(update, metadata, "invoice_number", transactionRequest.getInvoiceNumber(), false);
    addMetaData(update, metadata, "purchase_order_number", transactionRequest.getPurchaseOrderNumber(), false);
    return metadata;
  }

  /**
   * See <a href="https://stripe.com/docs/api/customers/create?lang=java">Create a customer</a>.
   */
  private static void addCustomerParams(
      CreditCard creditCard,
      CustomerCreateParams.Builder builder
  ) {
    // Unused: account_balance
    // Unused: address
    // Unused: coupon
    // Unused: default_source
    addParam(false, builder::setDescription, creditCard.getComments());
    addParam(false, builder::setEmail, creditCard.getEmail());
    // Unused: invoice_prefix
    // Unused: invoice_settings
    addParam(false, builder::putAllMetadata, makeCustomerMetadata(creditCard, false));
    addParam(false, builder::setName, CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
    // Unused: payment_method
    addParam(false, builder::setPhone, creditCard.getPhone());
    // Unused: preferred_locales
    // Unused: shipping
    // source: set other places as-needed
    // Unused: tax_exempt: TODO?
    // Unused: tax_id_data
    // Unused: tax_info
  }

  /**
   * See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.
   */
  private static void addCustomerParams(
      CreditCard creditCard,
      CustomerUpdateParams.Builder builder
  ) {
    if (UPDATE_WITH_MAP_API) {
      throw new AssertionError();
    }
    // Unused: account_balance
    // Unused: address
    // Unused: coupon
    // Unused: default_source
    addParam(true, builder::setDescription, creditCard.getComments());
    addParam(true, builder::setEmail, creditCard.getEmail());
    // Unused: invoice_prefix
    // Unused: invoice_settings
    addParam(true, builder::putAllMetadata, makeCustomerMetadata(creditCard, true));
    addParam(true, builder::setName, CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
    // Unused: payment_method
    addParam(true, builder::setPhone, creditCard.getPhone());
    // Unused: preferred_locales
    // Unused: shipping
    // source: set other places as-needed
    // Unused: tax_exempt: TODO?
    // Unused: tax_id_data
    // Unused: tax_info
  }

  /**
   * Adds customer parameters.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/customers/create?lang=java">Create a customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.</li>
   * </ol>
   */
  private static void addCustomerParams(
      CreditCard creditCard,
      boolean update,
      Map<String, Object> customerParams
  ) {
    if (update && !UPDATE_WITH_MAP_API) {
      throw new AssertionError();
    }
    // Unused: account_balance
    // Unused: address
    // Unused: coupon
    // Unused: default_source
    addParam(update, customerParams, "description", creditCard.getComments());
    addParam(update, customerParams, "email", creditCard.getEmail());
    // Unused: invoice_prefix
    // Unused: invoice_settings
    addParam(update, customerParams, "metadata", makeCustomerMetadata(creditCard, update));
    addParam(update, customerParams, "name", CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
    // Unused: payment_method
    addParam(update, customerParams, "phone", creditCard.getPhone());
    // Unused: preferred_locales
    // Unused: shipping
    // source: set other places as-needed
    // Unused: tax_exempt: TODO?
    // Unused: tax_id_data
    // Unused: tax_info
  }

  /**
   * See <a href="https://stripe.com/docs/api/cards/update?lang=java">Update a card</a>.
   */
  private static void addCardParams(
      CreditCard creditCard,
      CardUpdateOnCustomerParams.Builder cardParams
  ) {
    if (UPDATE_WITH_MAP_API) {
      throw new AssertionError();
    }
    // object: set to "card" other places as-needed
    // number: set other places as-needed
    // exp_month: set other places as-needed
    // exp_year: set other places as-needed
    // cvc: set other places as-needed
    // Unused: currency
    addParam(true, cardParams::setName, CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
    // Unused: default_for_currency
    addParam(true, cardParams::setAddressLine1, creditCard.getStreetAddress1());
    addParam(true, cardParams::setAddressLine2, creditCard.getStreetAddress2());
    addParam(true, cardParams::setAddressCity, creditCard.getCity());
    addParam(true, cardParams::setAddressState, creditCard.getState());
    addParam(true, cardParams::setAddressZip, creditCard.getPostalCode());
    addParam(true, cardParams::setAddressCountry, creditCard.getCountryCode());
  }

  /**
   * Adds card parameters.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/cards/create?lang=java">Create a card</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/update?lang=java">Update a card</a>.</li>
   * </ol>
   */
  private static void addCardParams(
      CreditCard creditCard,
      boolean update,
      Map<String, Object> cardParams
  ) {
    if (update && !UPDATE_WITH_MAP_API) {
      throw new AssertionError();
    }
    // object: set to "card" other places as-needed
    // number: set other places as-needed
    // exp_month: set other places as-needed
    // exp_year: set other places as-needed
    // cvc: set other places as-needed
    // Unused: currency
    addParam(update, cardParams, "name", CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
    // Unused: default_for_currency
    addParam(update, cardParams, "address_line1", creditCard.getStreetAddress1());
    addParam(update, cardParams, "address_line2", creditCard.getStreetAddress2());
    addParam(update, cardParams, "address_city", creditCard.getCity());
    addParam(update, cardParams, "address_state", creditCard.getState());
    addParam(update, cardParams, "address_zip", creditCard.getPostalCode());
    addParam(update, cardParams, "address_country", creditCard.getCountryCode());
  }

  /**
   * See <a href="https://stripe.com/docs/api/payment_methods/create?lang=java">Create a PaymentMethod</a>.
   */
  private static void addPaymentMethodParams(
      CreditCard creditCard,
      PaymentMethodCreateParams.Builder paymentMethodParams
  ) {
    // type: set to "card" other places as-needed
    PaymentMethodCreateParams.BillingDetails.Address address;
    {
      PaymentMethodCreateParams.BillingDetails.Address.Builder builder = PaymentMethodCreateParams.BillingDetails.Address.builder();
      boolean paramSet = false;
      paramSet |= addParam(false, builder::setCity, creditCard.getCity());
      paramSet |= addParam(false, builder::setCountry, creditCard.getCountryCode());
      paramSet |= addParam(false, builder::setLine1, creditCard.getStreetAddress1());
      paramSet |= addParam(false, builder::setLine2, creditCard.getStreetAddress2());
      paramSet |= addParam(false, builder::setPostalCode, creditCard.getPostalCode());
      paramSet |= addParam(false, builder::setState, creditCard.getState());
      address = paramSet ? builder.build() : null;
    }
    PaymentMethodCreateParams.BillingDetails billingDetails;
    {
      PaymentMethodCreateParams.BillingDetails.Builder builder = PaymentMethodCreateParams.BillingDetails.builder();
      boolean paramSet = false;
      paramSet |= addParam(false, builder::setAddress, address);
      paramSet |= addParam(false, builder::setEmail, creditCard.getEmail());
      paramSet |= addParam(false, builder::setName, CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
      paramSet |= addParam(false, builder::setPhone, creditCard.getPhone());
      billingDetails = paramSet ? builder.build() : null;
    }
    addParam(false, paymentMethodParams::setBillingDetails, billingDetails);
  }

  /**
   * See <a href="https://stripe.com/docs/api/payment_methods/update?lang=java">Update a PaymentMethod</a>.
   */
  private static void addPaymentMethodParams(
      CreditCard creditCard,
      PaymentMethodUpdateParams.Builder paymentMethodParams
  ) {
    // type: set to "card" other places as-needed
    PaymentMethodUpdateParams.BillingDetails.Address address;
    {
      PaymentMethodUpdateParams.BillingDetails.Address.Builder builder = PaymentMethodUpdateParams.BillingDetails.Address.builder();
      boolean paramSet = false;
      paramSet |= addParam(false, builder::setCity, creditCard.getCity());
      paramSet |= addParam(false, builder::setCountry, creditCard.getCountryCode());
      paramSet |= addParam(false, builder::setLine1, creditCard.getStreetAddress1());
      paramSet |= addParam(false, builder::setLine2, creditCard.getStreetAddress2());
      paramSet |= addParam(false, builder::setPostalCode, creditCard.getPostalCode());
      paramSet |= addParam(false, builder::setState, creditCard.getState());
      address = paramSet ? builder.build() : null;
    }
    PaymentMethodUpdateParams.BillingDetails billingDetails;
    {
      PaymentMethodUpdateParams.BillingDetails.Builder builder = PaymentMethodUpdateParams.BillingDetails.builder();
      boolean paramSet = false;
      paramSet |= addParam(false, builder::setAddress, address);
      paramSet |= addParam(false, builder::setEmail, creditCard.getEmail());
      paramSet |= addParam(false, builder::setName, CreditCard.getFullName(creditCard.getFirstName(), creditCard.getLastName()));
      paramSet |= addParam(false, builder::setPhone, creditCard.getPhone());
      billingDetails = paramSet ? builder.build() : null;
    }
    addParam(false, paymentMethodParams::setBillingDetails, billingDetails);
  }

  /**
   * See <a href="https://stripe.com/docs/api/payment_methods/create?lang=java">Create a PaymentMethod</a>.
   */
  private static PaymentMethodCreateParams makePaymentMethodParams(
      CreditCard creditCard,
      String cardNumber,
      byte expirationMonth, // TODO: 3.0: Make nullable Byte
      short expirationYear, // TODO: 3.0: Make nullable Short
      String cardCode
  ) {
    PaymentMethodCreateParams.CardDetails cardParams;
    {
      PaymentMethodCreateParams.CardDetails.Builder builder = PaymentMethodCreateParams.CardDetails.builder();
      builder.setExpMonth(expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH ? null : (long) expirationMonth);
      builder.setExpYear(expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR ? null : (long) expirationYear);
      addParam(false, builder::setNumber, CreditCard.numbersOnly(cardNumber));
      addParam(false, builder::setCvc, cardCode);
      cardParams = builder.build();
    }
    PaymentMethodCreateParams paymentMethodParams;
    {
      PaymentMethodCreateParams.Builder builder = PaymentMethodCreateParams.builder();
      builder.setType(PaymentMethodCreateParams.Type.CARD);
      builder.setCard(cardParams);
      addPaymentMethodParams(creditCard, builder);
      paymentMethodParams = builder.build();
    }
    return paymentMethodParams;
  }

  /**
   * See {@link Stripe#makePaymentMethodParams(com.aoapps.payments.CreditCard, java.lang.String, byte, short, java.lang.String)}.
   */
  private static PaymentMethodCreateParams makePaymentMethodParams(CreditCard creditCard) {
    return makePaymentMethodParams(
        creditCard,
        creditCard.getCardNumber(),
        creditCard.getExpirationMonth(),
        creditCard.getExpirationYear(),
        creditCard.getCardCode()
    );
  }

  /**
   * See <a href="https://stripe.com/docs/api/payment_intents/create?lang=java">Create a PaymentIntent</a>.
   */
  private static PaymentIntentCreateParams.Shipping makeShippingParams(TransactionRequest transactionRequest, CreditCard creditCard) {
    PaymentIntentCreateParams.Shipping.Address address;
    {
      PaymentIntentCreateParams.Shipping.Address.Builder builder = PaymentIntentCreateParams.Shipping.Address.builder();
      boolean paramSet = false;
      paramSet |= addParam(false, builder::setLine1, transactionRequest.getShippingStreetAddress1());
      paramSet |= addParam(false, builder::setCity, transactionRequest.getShippingCity());
      paramSet |= addParam(false, builder::setCountry, transactionRequest.getShippingCountryCode());
      paramSet |= addParam(false, builder::setLine2, transactionRequest.getShippingStreetAddress2());
      paramSet |= addParam(false, builder::setPostalCode, transactionRequest.getShippingPostalCode());
      paramSet |= addParam(false, builder::setState, transactionRequest.getShippingState());
      address = paramSet ? builder.build() : null;
    }
    String shippingName = CreditCard.getFullName(transactionRequest.getShippingFirstName(), transactionRequest.getShippingLastName());
    if (shippingName != null && shippingName.isEmpty()) {
      shippingName = null;
    }
    PaymentIntentCreateParams.Shipping shipping;
    {
      // When no shipping address and no shipping name, do not set shipping at all
      if (address == null && shippingName == null) {
        shipping = null;
      } else {
        PaymentIntentCreateParams.Shipping.Builder shippingBuilder = PaymentIntentCreateParams.Shipping.builder();
        boolean paramSet = false;
        paramSet |= addParam(false, shippingBuilder::setAddress, address);
        paramSet |= addParam(false, shippingBuilder::setName, shippingName);
        // Unused: carrier addParam(update, shippingParams, "address", addressParams);
        paramSet |= addParam(false, shippingBuilder::setPhone, creditCard.getPhone());
        // Unused: tracking_number
        shipping = paramSet ? shippingBuilder.build() : null;
      }
    }
    return shipping;
  }

  private static class ConvertedError {

    private final TransactionResult.CommunicationResult communicationResult;
    private final String providerErrorCode;
    private final TransactionResult.ErrorCode errorCode;
    private final String providerErrorMessage;
    private final AuthorizationResult.DeclineReason declineReason;
    private final String providerReplacementMaskedCardNumber;
    private final String replacementMaskedCardNumber;
    private final String providerReplacementExpiration;
    private final Byte replacementExpirationMonth;
    private final Short replacementExpirationYear;

    private ConvertedError(
        TransactionResult.CommunicationResult communicationResult,
        String providerErrorCode,
        TransactionResult.ErrorCode errorCode,
        String providerErrorMessage,
        AuthorizationResult.DeclineReason declineReason,
        String providerReplacementMaskedCardNumber,
        String replacementMaskedCardNumber,
        String providerReplacementExpiration,
        Byte replacementExpirationMonth,
        Short replacementExpirationYear
    ) {
      this.communicationResult = communicationResult;
      this.providerErrorCode = providerErrorCode;
      this.errorCode = errorCode;
      this.providerErrorMessage = providerErrorMessage;
      this.declineReason = declineReason;
      this.providerReplacementMaskedCardNumber = providerReplacementMaskedCardNumber;
      this.replacementMaskedCardNumber = replacementMaskedCardNumber;
      this.providerReplacementExpiration = providerReplacementExpiration;
      this.replacementExpirationMonth = replacementExpirationMonth;
      this.replacementExpirationYear = replacementExpirationYear;
    }
  }

  private static final String MASK_8;

  static {
    char[] mask8chars = new char[8];
    Arrays.fill(mask8chars, MASK_CHARACTER);
    MASK_8 = new String(mask8chars);
  }

  private static final String MASK_9 = MASK_8 + MASK_CHARACTER;

  private static final String MASK_10 = MASK_9 + MASK_CHARACTER;

  private static final String MASK_11 = MASK_10 + MASK_CHARACTER;

  private static String getProviderReplacementCombined(Object val1, Object val2) {
    return Objects.toString(val1, "") + ',' + Objects.toString(val2, "");
  }

  /**
   * Generates a replacement masked card number given the old masked card number,
   * new brand, and new last4.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/object?lang=java">The PaymentMethod object</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/object?lang=java">The card object</a>.</li>
   * <li>See <a href="https://wikipedia.org/wiki/Payment_card_number#Issuer_identification_number_(IIN)">Issuer identification number (IIN)</a>.</li>
   * </ol>
   *
   * @param  maskedCardNumber  The old masked card number, when available.
   * @param  brand  The brand of a possible replacement card, when available.
   * @param  last4  The last four digits of a possible replacement card, when available.
   *
   * @return  The updated masked card number or {@code null} when unchanged or unable to determine a reasonable and unambiguous mapping.
   */
  private String getReplacementMaskedCardNumber(String maskedCardNumber, String brand, String last4, PrintWriter warningOut) {
    final String replacementMaskedCardNumber;
    if (brand == null || last4 == null) {
      // If there is no brand or last4, there is nothing we can do
      replacementMaskedCardNumber = null;
    } else if (!last4.equals(CreditCard.numbersOnly(last4))) {
      // If last4 is not all digits, ignore
      if (warningOut != null) {
        warningOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getReplacementMaskedCardNumber: last4 is not all digits, ignoring: " + last4);
      } else if (logger.isLoggable(Level.WARNING)) {
        logger.log(Level.WARNING, "last4 is not all digits, ignoring: " + last4);
      }
      replacementMaskedCardNumber = null;
    } else if (last4.length() != 4) {
      // If last4 is not length 4, ignore
      if (warningOut != null) {
        warningOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getReplacementMaskedCardNumber: last4 is not length 4, ignoring: " + last4);
      } else if (logger.isLoggable(Level.WARNING)) {
        logger.log(Level.WARNING, "last4 is not length 4, ignoring: " + last4);
      }
      replacementMaskedCardNumber = null;
    } else {
      // If the last four digits match the old masked card number, assume not changed.
      String oldDigits = CreditCard.numbersOnly(maskedCardNumber, true);
      if (oldDigits != null && oldDigits.endsWith(last4)) {
        // We won't bother comparing brand in this case.  It is unlikely a card is replaced with a new type at all, and very unlikely with same last-four digits.
        replacementMaskedCardNumber = null;
      } else if (
          "amex".equals(brand) // PaymentMethod API
              || "American Express".equals(brand) // Card API
      ) {
        // Start: 34, 37
        // Length: 15
        replacementMaskedCardNumber = "3" + UNKNOWN_DIGIT + MASK_9 + last4;
        assert replacementMaskedCardNumber.length() == 15;
      } else if (
          "diners".equals(brand) // PaymentMethod API
              || "Diners Club".equals(brand) // Card API
      ) {
        // TODO: No unambiguous mapping.  Version 2.0 of API will handle this better with type + last4 stored
        replacementMaskedCardNumber = UNKNOWN_MIDDLE + last4;
      } else if (
          "discover".equals(brand) // PaymentMethod API
              || "Discover".equals(brand) // Card API
      ) {
        // TODO: There are other prefixes than this, but this matches the expectations of our very old code
        replacementMaskedCardNumber = "6011" + MASK_8 + last4;
        // TODO: There are other lengths, but this matches the expectations of our very old code
        assert replacementMaskedCardNumber.length() == 16;
      } else if (
          "jcb".equals(brand) // PaymentMethod API
              || "JCB".equals(brand) // Card API
      ) {
        // TODO: No unambiguous mapping.  Version 2.0 of API will handle this better with type + last4 stored
        replacementMaskedCardNumber = UNKNOWN_MIDDLE + last4;
      } else if (
          "mastercard".equals(brand) // PaymentMethod API
              || "MasterCard".equals(brand) // Card API
      ) {
        // TODO: There are other prefixes than this, but this matches the expectations of our very old code
        replacementMaskedCardNumber = "5" + UNKNOWN_DIGIT + MASK_10 + last4;
        // TODO: There are other lengths, but this matches the expectations of our very old code
        assert replacementMaskedCardNumber.length() == 16;
      } else if (
          "unionpay".equals(brand) // PaymentMethod API
              || "UnionPay".equals(brand) // Card API
      ) {
        // Start: 62
        // Length: 16-19
        replacementMaskedCardNumber = "62" + UNKNOWN_MIDDLE + last4;
      } else if (
          "visa".equals(brand) // PaymentMethod API
              || "Visa".equals(brand) // Card API
      ) {
        // Start: 4
        // Length: 16
        replacementMaskedCardNumber = "4" + MASK_11 + last4;
        assert replacementMaskedCardNumber.length() == 16;
      } else {
        if (
            !"unknown".equalsIgnoreCase(brand) // PaymentMethod API
                && !"Unknown".equalsIgnoreCase(brand) // Card API
        ) {
          if (warningOut != null) {
            warningOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getReplacementMaskedCardNumber: Unexpected brand: " + brand);
          } else if (logger.isLoggable(Level.WARNING)) {
            logger.log(Level.WARNING, "Unexpected brand: " + brand);
          }
        }
        replacementMaskedCardNumber = null;
      }
    }
    return replacementMaskedCardNumber;
  }

  /**
   * Converts Stripe's {@link Long} representation of an expiration month to a {@link Byte}.
   *
   * @see  SafeMath#castByte(long)
   */
  private static Byte safeCastMonth(Long expMonth) {
    return expMonth == null ? null : SafeMath.castByte(expMonth);
  }

  /**
   * Converts Stripe's {@link Long} representation of an expiration year to a {@link Short}.
   *
   * @see  SafeMath#castShort(long)
   */
  private static Short safeCastYear(Long expYear) {
    return expYear == null ? null : SafeMath.castShort(expYear);
  }

  /**
   * Converts Stripe errors to API errors.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/errors?lang=java">Errors</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/errors/handling?lang=java">Handling errors</a>.</li>
   * </ol>
   */
  private ConvertedError convertError(String maskedCardNumber, Byte expirationMonth, Short expirationYear, StripeException e, PrintWriter warningOut) {
    String requestId = e.getRequestId(); // TODO: Return this via API?
    final Integer statusCode = e.getStatusCode();
    StripeError stripeError = e.getStripeError();

    // For some errors that could be handled programmatically, a short string indicating the error code reported.
    String code = stripeError == null ? null : stripeError.getCode();
    if (code == null) {
      code = e.getCode();
    }

    // For card errors, the ID of the failed charge.
    // TODO: Make this available through response API somehow?  Becoming a link in web forms?
    String docUrl = stripeError == null ? null : stripeError.getDocUrl();

    // A human-readable message providing more details about the error.
    // For card errors, these messages can be shown to your users.
    String message = stripeError == null ? null : stripeError.getMessage();
    if (message == null) {
      message = e.getMessage();
      if (message == null || message.trim().isEmpty()) {
        message = e.toString();
      }
    }

    // The PaymentIntent object for errors returned on a request involving a PaymentIntent.
    // TODO: What to do this paymentIntent?
    PaymentIntent paymentIntent = stripeError == null ? null : stripeError.getPaymentIntent();

    // The PaymentMethod object for errors returned on a request involving a PaymentMethod.
    PaymentMethod paymentMethod = stripeError == null ? null : stripeError.getPaymentMethod();
    PaymentMethod.Card card = paymentMethod == null ? null : paymentMethod.getCard();

    // The source object for errors returned on a request involving a source.
    // TODO: What to do with paymentSource?
    PaymentSource source = stripeError == null ? null : stripeError.getSource();

    String providerReplacementMaskedCardNumber;
    String replacementMaskedCardNumber;
    String providerReplacementExpiration;
    Byte replacementExpirationMonth;
    Short replacementExpirationYear;
    if (card != null) {
      String brand = card.getBrand();
      String last4 = card.getLast4();
      providerReplacementMaskedCardNumber = getProviderReplacementCombined(brand, last4);
      replacementMaskedCardNumber = getReplacementMaskedCardNumber(maskedCardNumber, brand, last4, warningOut);
      Long expMonth = card.getExpMonth();
      Long expYear = card.getExpYear();
      providerReplacementExpiration = getProviderReplacementCombined(expMonth, expYear);
      replacementExpirationMonth = safeCastMonth(expMonth);
      replacementExpirationYear = safeCastYear(expYear);
      if (
          expirationMonth != null && expirationMonth.equals(replacementExpirationMonth)
              && expirationYear != null && expirationYear.equals(replacementExpirationYear)
      ) {
        replacementExpirationMonth = null;
        replacementExpirationYear = null;
      }
    } else {
      providerReplacementMaskedCardNumber = null;
      replacementMaskedCardNumber = null;
      providerReplacementExpiration = null;
      replacementExpirationMonth = null;
      replacementExpirationYear = null;
    }

    if (
        // Is subclass of InvalidRequestException, must go before it
        e instanceof RateLimitException
    ) {
      return new ConvertedError(
          TransactionResult.CommunicationResult.GATEWAY_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, ""),
          TransactionResult.ErrorCode.RATE_LIMIT,
          message,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (
        e instanceof CardException
            // // Is parent class of RateLimitException, must go after it
            || e instanceof InvalidRequestException
    ) {
      // If the error is parameter-specific, the parameter related to the error.
      // TODO: Map param to series of INVALID_... error codes
      String param = stripeError == null ? null : stripeError.getParam();

      // See https://stripe.com/docs/declines#issuer-declines
      // See https://stripe.com/docs/declines/codes
      String declineCode = stripeError == null ? null : stripeError.getDeclineCode();

      // For card errors, the ID of the failed charge.
      // Unused: String charge = stripeError == null ? null : stripeError.getCharge();

      // Get values from specific exception types.  TODO: Necessary or will this always match StripeError?
      if (e instanceof CardException) {
        CardException ce = (CardException) e;
        if (param == null) {
          param = ce.getParam();
        }
        if (declineCode == null) {
          declineCode = ce.getDeclineCode();
        }
        // Unused: if (charge == null) {
        //    charge = ce.getCharge();
        // }
      } else if (e instanceof InvalidRequestException) {
        InvalidRequestException ire = (InvalidRequestException) e;
        if (param == null) {
          param = ire.getParam();
        }
      }

      // Convert to ErrorCode
      // https://stripe.com/docs/error-codes
      // errorCode is not used for declineReason, one or other only
      final TransactionResult.ErrorCode errorCode;
      final AuthorizationResult.DeclineReason declineReason;
      if ("amount_too_large".equals(code)) {
        errorCode = TransactionResult.ErrorCode.AMOUNT_TOO_HIGH;
        declineReason = null;
      } else if ("amount_too_small".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_AMOUNT;
        declineReason = null;
      } else if ("api_key_expired".equals(code)) {
        // TODO: Will this only be CardException, or should we convert based on code regardless of exception type?
        errorCode = TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET;
        declineReason = null;
      } else if ("balance_insufficient".equals(code)) {
        errorCode = null;
        declineReason = AuthorizationResult.DeclineReason.INSUFFICIENT_FUNDS;
      } else if ("card_declined".equals(code)) {
        // Handle declined codes: https://stripe.com/docs/declines/codes
        if ("approve_with_id".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN_5_MINUTES;
          declineReason = null;
        } else if ("call_issuer".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("card_not_supported".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.CARD_TYPE_NOT_SUPPORTED;
          declineReason = null;
        } else if ("card_velocity_exceeded".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.INSUFFICIENT_FUNDS;
        } else if ("currency_not_supported".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.CURRENCY_NOT_SUPPORTED;
          declineReason = null;
        } else if ("do_not_honor".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("do_not_try_again".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("duplicate_transaction".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.DUPLICATE;
          declineReason = null;
        } else if ("expired_card".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.EXPIRED_CARD;
        } else if ("fraudulent".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.FRAUD_DETECTED;
        } else if ("generic_decline".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("incorrect_number".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.INVALID_CARD_NUMBER;
          declineReason = null;
        } else if ("incorrect_cvc".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.CVV2_MISMATCH;
        } else if ("incorrect_pin".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN; // TODO: New DeclineReason
        } else if ("incorrect_zip".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.AVS_FAILURE;
        } else if ("insufficient_funds".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.INSUFFICIENT_FUNDS;
        } else if ("invalid_account".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("invalid_amount".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.INVALID_AMOUNT;
          declineReason = null;
        } else if ("invalid_cvc".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.CVV2_MISMATCH;
        } else if ("invalid_expiry_year".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.INVALID_EXPIRATION_DATE;
          declineReason = null;
        } else if ("invalid_number".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.INVALID_CARD_NUMBER;
          declineReason = null;
        } else if ("invalid_pin".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.UNKNOWN; // TODO: New ErrorCode
          declineReason = null;
        } else if ("issuer_not_available".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN_5_MINUTES;
          declineReason = null;
        } else if ("lost_card".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.STOLEN_OR_LOST_CARD;
        } else if ("merchant_blacklist".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("new_account_information_available".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("no_action_taken".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("not_permitted".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("pickup_card".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.PICK_UP_CARD;
        } else if ("pin_try_exceeded".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN; // TODO: New DeclineReason
        } else if ("processing_error".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN;
          declineReason = null;
        } else if ("reenter_transaction".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN;
          declineReason = null;
        } else if ("restricted_card".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("revocation_of_all_authorizations".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("revocation_of_authorization".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("security_violation".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET;
          declineReason = null;
        } else if ("service_not_allowed".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("stolen_card".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.STOLEN_OR_LOST_CARD;
        } else if ("stop_payment_order".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("testmode_decline".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
          declineReason = null;
        } else if ("transaction_not_allowed".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        } else if ("try_again_later".equals(declineCode)) {
          errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN_5_MINUTES;
          declineReason = null;
        } else if ("withdrawal_count_limit_exceeded".equals(declineCode)) {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.INSUFFICIENT_FUNDS;
        } else {
          errorCode = null;
          declineReason = AuthorizationResult.DeclineReason.UNKNOWN;
        }
      } else if (
          "charge_already_captured".equals(code)
              || "charge_already_refunded".equals(code)
              || "charge_disputed".equals(code)
      ) {
        errorCode = TransactionResult.ErrorCode.DUPLICATE; // TODO: New ErrorCode?
        declineReason = null;
      } else if ("charge_exceeds_source_limit".equals(code)) {
        errorCode = null;
        declineReason = AuthorizationResult.DeclineReason.VOLUME_EXCEEDED_1_DAY;
      } else if ("country_unsupported".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_COUNTRY_CODE;
        declineReason = null;
      } else if ("email_invalid".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_EMAIL;
        declineReason = null;
      } else if ("expired_card".equals(code)) {
        errorCode = TransactionResult.ErrorCode.CARD_EXPIRED;
        declineReason = null;
      } else if ("incorrect_address".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_ADDRESS;
        declineReason = null;
      } else if ("incorrect_cvc".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_CODE;
        declineReason = null;
      } else if ("incorrect_number".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_NUMBER;
        declineReason = null;
      } else if ("incorrect_zip".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_POSTAL_CODE;
        declineReason = null;
      } else if ("invalid_card_type".equals(code)) {
        errorCode = TransactionResult.ErrorCode.CARD_TYPE_NOT_SUPPORTED;
        declineReason = null;
      } else if ("invalid_charge_amount".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_AMOUNT;
        declineReason = null;
      } else if ("invalid_cvc".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_CODE;
        declineReason = null;
      } else if (
          "invalid_expiry_month".equals(code)
              || "invalid_expiry_year".equals(code)
      ) {
        errorCode = TransactionResult.ErrorCode.INVALID_EXPIRATION_DATE;
        declineReason = null;
      } else if ("invalid_number".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_NUMBER;
        declineReason = null;
      } else if ("livemode_mismatch".equals(code)) {
        errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
        declineReason = null;
      } else if ("missing".equals(code)) {
        errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
        declineReason = null;
      } else if (
          "parameter_invalid_empty".equals(code)
              || "parameter_invalid_integer".equals(code)
              || "parameter_invalid_string_blank".equals(code)
              || "parameter_invalid_string_empty".equals(code)
              || "parameter_missing".equals(code)
      ) {
        // TODO: Map to specific "param"
        errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
        declineReason = null;
      } else if (
          "parameter_unknown".equals(code)
              || "parameters_exclusive".equals(code)
      ) {
        // TODO: Map to specific "param"
        errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
        declineReason = null;
      } else if ("payment_method_unactivated".equals(code)) {
        errorCode = TransactionResult.ErrorCode.CARD_TYPE_NOT_SUPPORTED;
        declineReason = null;
      } else if ("platform_api_key_expired".equals(code)) {
        errorCode = TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET;
        declineReason = null;
      } else if ("postal_code_invalid".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_POSTAL_CODE;
        declineReason = null;
      } else if ("processing_error".equals(code)) {
        errorCode = TransactionResult.ErrorCode.ERROR_TRY_AGAIN;
        declineReason = null;
      } else if ("rate_limit".equals(code)) {
        errorCode = TransactionResult.ErrorCode.RATE_LIMIT;
        declineReason = null;
      } else if ("secret_key_required".equals(code)) {
        errorCode = TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET;
        declineReason = null;
      } else if ("shipping_calculation_failed".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_SHIPPING_AMOUNT;
        declineReason = null;
      } else if ("state_unsupported".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CARD_STATE;
        declineReason = null;
      } else if ("tax_id_invalid".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_CUSTOMER_TAX_ID;
        declineReason = null;
      } else if ("taxes_calculation_failed".equals(code)) {
        errorCode = TransactionResult.ErrorCode.INVALID_TAX_AMOUNT;
        declineReason = null;
      } else if ("testmode_charges_only".equals(code)) {
        errorCode = TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR;
        declineReason = null;
      } else if ("tls_version_unsupported".equals(code)) {
        errorCode = TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET;
        declineReason = null;
      } else if (
          "token_already_used".equals(code)
              || "token_in_use".equals(code)
      ) {
        errorCode = TransactionResult.ErrorCode.DUPLICATE;
        declineReason = null;
      } else {
        errorCode = TransactionResult.ErrorCode.UNKNOWN;
        declineReason = null;
      }
      return new ConvertedError(
          declineReason == null ? TransactionResult.CommunicationResult.GATEWAY_ERROR : TransactionResult.CommunicationResult.SUCCESS,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, "") + "," + Objects.toString(param, "") + "," + Objects.toString(declineCode, ""),
          errorCode,
          message,
          declineReason,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (
        e instanceof AuthenticationException
            || e instanceof PermissionException
    ) {
      return new ConvertedError(
          TransactionResult.CommunicationResult.GATEWAY_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, ""),
          TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR,
          message,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (e instanceof OAuthException) {
      OAuthError oauthError = ((OAuthException) e).getOauthError();
      String errorDescription = oauthError == null ? null : oauthError.getErrorDescription();
      return new ConvertedError(
          TransactionResult.CommunicationResult.GATEWAY_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, "") + "," + Objects.toString(oauthError == null ? null : oauthError.getError(), ""),
          TransactionResult.ErrorCode.PROVIDER_CONFIGURATION_ERROR,
          errorDescription == null ? message : errorDescription,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (e instanceof IdempotencyException) {
      return new ConvertedError(
          TransactionResult.CommunicationResult.GATEWAY_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, ""),
          TransactionResult.ErrorCode.DUPLICATE,
          message,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (
        e instanceof ApiConnectionException
            || e instanceof ApiException
            || e instanceof EventDataObjectDeserializationException
    ) {
      return new ConvertedError(
          TransactionResult.CommunicationResult.IO_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, ""),
          TransactionResult.ErrorCode.ERROR_TRY_AGAIN,
          message,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    if (e instanceof SignatureVerificationException) {
      String sigHeader = ((SignatureVerificationException) e).getSigHeader();
      return new ConvertedError(
          TransactionResult.CommunicationResult.GATEWAY_ERROR,
          Objects.toString(statusCode, "") + "," + Objects.toString(code, "") + "," + Objects.toString(sigHeader, ""),
          TransactionResult.ErrorCode.GATEWAY_SECURITY_GUIDELINES_NOT_MET,
          message,
          null,
          providerReplacementMaskedCardNumber,
          replacementMaskedCardNumber,
          providerReplacementExpiration,
          replacementExpirationMonth,
          replacementExpirationYear
      );
    }
    // Note: This will not happen unless a new subclass of StripeException is introduced.
    return new ConvertedError(
        TransactionResult.CommunicationResult.GATEWAY_ERROR,
        Objects.toString(statusCode, "") + "," + Objects.toString(code, ""),
        TransactionResult.ErrorCode.UNKNOWN,
        message,
        null,
        providerReplacementMaskedCardNumber,
        replacementMaskedCardNumber,
        providerReplacementExpiration,
        replacementExpirationMonth,
        replacementExpirationYear
    );
  }

  private static AuthorizationResult.CvvResult getCvvResult(String providerCvvResult) {
    if (providerCvvResult == null) {
      return AuthorizationResult.CvvResult.CVV2_NOT_PROVIDED_BY_MERCHANT;
    } else {
      if ("pass".equals(providerCvvResult)) {
        return AuthorizationResult.CvvResult.MATCH;
      } else if ("fail".equals(providerCvvResult)) {
        return AuthorizationResult.CvvResult.NO_MATCH;
      } else if ("unavailable".equals(providerCvvResult)) {
        return AuthorizationResult.CvvResult.NOT_PROCESSED;
      } else if ("unchecked".equals(providerCvvResult)) {
        return AuthorizationResult.CvvResult.NOT_SUPPORTED_BY_ISSUER;
      } else {
        return AuthorizationResult.CvvResult.UNKNOWN;
      }
    }
  }

  private static Pair<String, AuthorizationResult.AvsResult> getAvsResult(String addressResult, String zipResult) {
    final String providerAvsResult;
    final AuthorizationResult.AvsResult avsResult;
    if (addressResult != null) {
      if (zipResult != null) {
        // Both address and ZIP
        providerAvsResult = addressResult + "," + zipResult;
        if ("pass".equals(addressResult) && "pass".equals(zipResult)) {
          // ADDRESS_Y_ZIP_5
          avsResult = AuthorizationResult.AvsResult.ADDRESS_Y_ZIP_5;
        } else if ("pass".equals(addressResult)) {
          // ADDRESS_Y_ZIP_N
          avsResult = AuthorizationResult.AvsResult.ADDRESS_Y_ZIP_N;
        } else if ("pass".equals(zipResult)) {
          // ADDRESS_N_ZIP_5
          avsResult = AuthorizationResult.AvsResult.ADDRESS_N_ZIP_5;
        } else if ("fail".equals(addressResult) && "fail".equals(zipResult)) {
          // ADDRESS_N_ZIP_N
          avsResult = AuthorizationResult.AvsResult.ADDRESS_N_ZIP_N;
        } else if ("unavailable".equals(addressResult) && "unavailable".equals(zipResult)) {
          // UNAVAILABLE
          avsResult = AuthorizationResult.AvsResult.UNAVAILABLE;
        } else if ("unchecked".equals(addressResult) && "unchecked".equals(zipResult)) {
          // SERVICE_NOT_SUPPORTED
          avsResult = AuthorizationResult.AvsResult.UNAVAILABLE;
        } else {
          avsResult = AuthorizationResult.AvsResult.UNKNOWN;
        }
      } else {
        // Address only
        providerAvsResult = addressResult + ",";
        if ("pass".equals(addressResult)) {
          avsResult = AuthorizationResult.AvsResult.ADDRESS_Y_ZIP_N;
        } else if ("fail".equals(addressResult)) {
          avsResult = AuthorizationResult.AvsResult.ADDRESS_N_ZIP_N;
        } else if ("unavailable".equals(addressResult)) {
          avsResult = AuthorizationResult.AvsResult.UNAVAILABLE;
        } else if ("unchecked".equals(addressResult)) {
          avsResult = AuthorizationResult.AvsResult.SERVICE_NOT_SUPPORTED;
        } else {
          avsResult = AuthorizationResult.AvsResult.UNKNOWN;
        }
      }
    } else {
      if (zipResult != null) {
        // ZIP only
        providerAvsResult = "," + zipResult;
        if ("pass".equals(zipResult)) {
          avsResult = AuthorizationResult.AvsResult.ADDRESS_N_ZIP_5;
        } else if ("fail".equals(zipResult)) {
          avsResult = AuthorizationResult.AvsResult.ADDRESS_N_ZIP_N;
        } else if ("unavailable".equals(zipResult)) {
          avsResult = AuthorizationResult.AvsResult.UNAVAILABLE;
        } else if ("unchecked".equals(zipResult)) {
          avsResult = AuthorizationResult.AvsResult.SERVICE_NOT_SUPPORTED;
        } else {
          avsResult = AuthorizationResult.AvsResult.UNKNOWN;
        }
      } else {
        providerAvsResult = ",";
        avsResult = AuthorizationResult.AvsResult.ADDRESS_NOT_PROVIDED;
      }
    }
    return Pair.of(providerAvsResult, avsResult);
  }

  @Override
  public SaleResult sale(TransactionRequest transactionRequest, CreditCard creditCard) {
    AuthorizationResult authorizationResult = saleOrAuthorize(transactionRequest, creditCard, true);
    return new SaleResult(
        authorizationResult,
        new CaptureResult(
            authorizationResult.getProviderId(),
            authorizationResult.getCommunicationResult(),
            authorizationResult.getProviderErrorCode(),
            authorizationResult.getErrorCode(),
            authorizationResult.getProviderErrorMessage(),
            authorizationResult.getProviderUniqueId()
        )
    );
  }

  @Override
  public AuthorizationResult authorize(TransactionRequest transactionRequest, CreditCard creditCard) {
    return saleOrAuthorize(transactionRequest, creditCard, false);
  }

  /**
   * Gets the ID of the default PaymentMethod for a Customer, setting an existing PaymentMethod to default when needed.
   * This can help recover from a failure between attaching a new PaymentMethod and setting it as the default.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/list?lang=java">List a Customer's PaymentMethods</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.</li>
   * </ol>
   */
  private Pair<Customer, String> getDefaultPaymentMethodId(Customer customer) throws StripeException {
    String paymentMethodId = customer.getInvoiceSettings().getDefaultPaymentMethod();
    String defaultSource = customer.getDefaultSource();
    // Ignore when is a default source, which should be updated through the legacy card API
    if (
        paymentMethodId != null
            && paymentMethodId.equals(defaultSource)
    ) {
      paymentMethodId = null;
    }
    if (paymentMethodId == null) {
      // Find up to 10 attached
      PaymentMethodCollection paymentMethodCollection = PaymentMethod.list(
          PaymentMethodListParams.builder()
              .setCustomer(customer.getId())
              .setType(PaymentMethodListParams.Type.CARD)
              .setLimit(100L)// Not performing pagination, it is very unlikely there will be more than 100 payment methods and all are the legacy card API
              .build(),
          options
      );
      if (paymentMethodCollection != null) {
        List<PaymentMethod> paymentMethods = paymentMethodCollection.getData();
        if (paymentMethods != null && !paymentMethods.isEmpty()) {
          // Set whatever the first one that is not from the legacy card API
          for (PaymentMethod paymentMethod : paymentMethods) {
            String id = paymentMethod.getId();
            if (!id.equals(defaultSource)) {
              paymentMethodId = id;
              customer = customer.update(
                  CustomerUpdateParams.builder()
                      .setInvoiceSettings(
                          CustomerUpdateParams.InvoiceSettings.builder()
                              .setDefaultPaymentMethod(paymentMethodId)
                              .build()
                      )
                      // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
                      .addExpand("sources")
                      .build(),
                  options
              );
              break;
            }
          }
        }
      }
    }
    return Pair.of(customer, paymentMethodId);
  }

  private static final BigInteger LONG_MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);

  /**
   * Converts an amount to a Long while checking bounds are between {@code 0} and {@link Long#MAX_VALUE}, inclusive.
   */
  private static Long convertAmountToLong(BigInteger value) {
    if (value == null) {
      return null;
    }
    if (value.signum() < 0) {
      throw new ArithmeticException("value < 0: " + value);
    }
    if (value.compareTo(LONG_MAX_VALUE) > 0) {
      throw new ArithmeticException("value > Long.MAX_VALUE: " + value);
    }
    return value.longValue();
  }

  /**
   * Implementation of {@link Stripe#sale(com.aoapps.payments.TransactionRequest, com.aoapps.payments.CreditCard)}
   * and {@link Stripe#authorize(com.aoapps.payments.TransactionRequest, com.aoapps.payments.CreditCard)}.
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/payment_intents/create?lang=java">Create a PaymentIntent</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_intents/confirm?lang=java">Confirm a PaymentIntent</a>.</li>
   * <li>See <a href="https://stripe.com/docs/payments/payment-intents/off-session?lang=java">Off-session Payments with Payment Intents</a>.</li>
   * <li>See <a href="https://stripe.com/docs/payments/payment-intents/quickstart?lang=java#manual-confirmation-flow">Manual confirmation quickstart</a>.</li>
   * <li>See <a href="https://stripe.com/docs/payments/payment-intents/usage?lang=java#paymentintent-status-overview">PaymentIntent status overview</a>.</li>
   * <li>See <a href="https://stripe.com/docs/payments/payment-intents/usage?lang=java#separate-auth-capture">Placing a hold on a card without charging</a>.</li>
   * <li>See <a href="https://stripe.com/docs/payments/payment-methods?lang=java#compatibility">Payment Methods Overview — Compatibility with Sources and Cards</a>.</li>
   * </ol>
   */
  private AuthorizationResult saleOrAuthorize(TransactionRequest transactionRequest, CreditCard creditCard, boolean capture) {
    Byte expirationMonth = creditCard.getExpirationMonth(); // TODO: 3.0: Nullable Byte
    if (expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH) {
      expirationMonth = null;
    }
    Short expirationYear = creditCard.getExpirationYear(); // TODO: 3.0: Nullable Short
    if (expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR) {
      expirationYear = null;
    }
    // Test mode not currently supported
    if (transactionRequest.getTestMode()) {
      throw new UnsupportedOperationException("Test mode not currently supported");
    }
    String customerId = null;
    try {
      String paymentMethodId;
      PaymentIntent paymentIntent;
      {
        // Convert amount into smallest unit
        BigDecimal totalAmount = transactionRequest.getTotalAmount();
        Currency currency = transactionRequest.getCurrency();
        int currencyDigits = currency.getDefaultFractionDigits();
        if (currencyDigits < 0) {
          throw new AssertionError("currencyDigits < 0: " + currencyDigits);
        }
        BigInteger amount = totalAmount.scaleByPowerOfTen(currencyDigits).toBigIntegerExact();
        // Create the PaymentIntent
        PaymentIntentCreateParams paymentIntentParams;
        {
          PaymentIntentCreateParams.Builder builder = PaymentIntentCreateParams.builder();
          builder.setAmount(convertAmountToLong(amount));
          // Java API 23.0.0 compatibility
          // See https://github.com/stripe/stripe-java/releases/tag/v23.0.0
          // API 2023-08-16 compatibility
          // See https://stripe.com/docs/upgrades#2023-08-16
          // See https://stripe.com/docs/api/payment_intents/object#payment_intent_object-automatic_payment_methods
          builder.setAutomaticPaymentMethods(PaymentIntentCreateParams.AutomaticPaymentMethods.builder()
              .setAllowRedirects(PaymentIntentCreateParams.AutomaticPaymentMethods.AllowRedirects.NEVER)
              .setEnabled(true)
              .build());
          builder.setCurrency(currency.getCurrencyCode());
          // Unused: application_fee_amount
          builder.setCaptureMethod(capture ? PaymentIntentCreateParams.CaptureMethod.AUTOMATIC : PaymentIntentCreateParams.CaptureMethod.MANUAL);
          builder.setConfirm(true);
          // API 2023-08-16 compatibility
          // invalid_request_error - automatic_payment_methods
          // You may only specify one of these parameters: automatic_payment_methods, confirmation_method
          // builder.setConfirmationMethod(PaymentIntentCreateParams.ConfirmationMethod.MANUAL);
          customerId = creditCard.getProviderUniqueId();
          if (customerId != null) {
            // Is a stored card
            builder.setCustomer(customerId);
          }
          addParam(false, builder::setDescription, transactionRequest.getDescription());
          addParam(false, builder::putAllMetadata, makePaymentIntentMetadata(transactionRequest, creditCard, false));
          // Unused: on_behalf_of
          if (customerId != null) {
            // Is a stored card
            Customer customer;
            {
              Pair<Customer, String> combined = getDefaultPaymentMethodId(
                  Customer.retrieve(
                      customerId,
                      // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
                      CustomerRetrieveParams.builder().addExpand("sources").build(),
                      options
                  )
              );
              customer = combined.getKey();
              paymentMethodId = combined.getValue();
            }
            if (paymentMethodId == null) {
              // Look for a default source for backward compatibility
              paymentMethodId = customer.getDefaultSource();
            }
          } else {
            // Is a new card
            paymentMethodId = PaymentMethod.create(makePaymentMethodParams(creditCard), options).getId();
          }
          builder.setPaymentMethod(paymentMethodId);
          // Unused: payment_method_types
          if (transactionRequest.getEmailCustomer()) {
            // TODO: The actual sending of email is configured on the Stripe account.  How to control through API?
            addParam(false, builder::setReceiptEmail, creditCard.getEmail());
          }
          // Unused: save_payment_method
          addParam(false, builder::setShipping, makeShippingParams(transactionRequest, creditCard));
          // Unused: source
          String orderNumber = transactionRequest.getOrderNumber();
          if (orderNumber != null) {
            orderNumber = orderNumber.trim();
            if (!orderNumber.isEmpty()) {
              // Avoid "The statement descriptor must contain at least one alphabetic character."
              boolean hasAlpha = false;
              for (int i = 0, len = orderNumber.length(), codePoint; i < len; i += Character.charCount(codePoint)) {
                codePoint = orderNumber.codePointAt(i);
                if (Character.isAlphabetic(codePoint)) {
                  hasAlpha = true;
                  break;
                }
              }
              String statementDescriptor = hasAlpha ? orderNumber : (STATEMENT_DESCRIPTOR_PREFIX + orderNumber);
              if (statementDescriptor.length() <= MAX_STATEMENT_DESCRIPTOR_LEN) {
                builder.setStatementDescriptor(statementDescriptor);
              }
            }
          }
          paymentIntentParams = builder.build();
        }
        // Unused: transfer_data
        // Unused: transfer_group
        paymentIntent = PaymentIntent.create(paymentIntentParams, options); // TODO: last_payment_error becomes StripeError in exception?
      }

      // Find the paymentMethod from the charges
      Charge latestCharge = paymentIntent.getLatestChargeObject();
      Charge.PaymentMethodDetails paymentMethodDetails = null;
      if (latestCharge != null) {
        if (paymentMethodId.equals(latestCharge.getPaymentMethod())) {
          paymentMethodDetails = latestCharge.getPaymentMethodDetails();
        } else if (logger.isLoggable(Level.WARNING)) {
          logger.log(Level.WARNING, "paymentMethodId != paymentIntent.latestCharge.paymentMethod: " + paymentMethodId + " != " + latestCharge.getPaymentMethod());
        }
      }
      Charge.PaymentMethodDetails.Card card = paymentMethodDetails == null ? null : paymentMethodDetails.getCard();
      Charge.PaymentMethodDetails.Card.Checks cardChecks = card == null ? null : card.getChecks();
      // CVC
      final String providerCvvResult = cardChecks == null ? null : cardChecks.getCvcCheck();
      final AuthorizationResult.CvvResult cvvResult;
      cvvResult = getCvvResult(providerCvvResult);
      // AVS
      final String providerAvsResult;
      final AuthorizationResult.AvsResult avsResult;
      {
        Pair<String, AuthorizationResult.AvsResult> combined = getAvsResult(
            cardChecks == null ? null : cardChecks.getAddressLine1Check(),
            cardChecks == null ? null : cardChecks.getAddressPostalCodeCheck()
        );
        providerAvsResult = combined.getLeft();
        avsResult = combined.getRight();
      }
      // TODO: FraudDetails fraudDetails = charge.getFraudDetails();
      // TODO: review reason
      // TODO: check "paid"?

      String providerReplacementMaskedCardNumber;
      String replacementMaskedCardNumber;
      String providerReplacementExpiration;
      Byte replacementExpirationMonth;
      Short replacementExpirationYear;
      if (card != null) {
        String brand = card.getBrand();
        String last4 = card.getLast4();
        providerReplacementMaskedCardNumber = getProviderReplacementCombined(brand, last4);
        replacementMaskedCardNumber = getReplacementMaskedCardNumber(creditCard.getMaskedCardNumber(), brand, last4, null);
        Long expMonth = card.getExpMonth();
        Long expYear = card.getExpYear();
        providerReplacementExpiration = getProviderReplacementCombined(expMonth, expYear);
        replacementExpirationMonth = safeCastMonth(expMonth);
        replacementExpirationYear = safeCastYear(expYear);
        if (
            expirationMonth != null && expirationMonth.equals(replacementExpirationMonth)
                && expirationYear != null && expirationYear.equals(replacementExpirationYear)
        ) {
          replacementExpirationMonth = null;
          replacementExpirationYear = null;
        }
      } else {
        providerReplacementMaskedCardNumber = null;
        replacementMaskedCardNumber = null;
        providerReplacementExpiration = null;
        replacementExpirationMonth = null;
        replacementExpirationYear = null;
      }

      // https://stripe.com/docs/payments/payment-intents/usage?lang=java#paymentintent-status-overview
      String status = paymentIntent.getStatus();

      if (
          // Must be "succeeded" when capturing or "requires_capture" for auth-only
          (capture ? "succeeded" : "requires_capture").equals(status)
      ) {
        final String approvalCode;
        if (latestCharge == null) {
          approvalCode = null;
        } else {
          approvalCode = latestCharge.getId();
        }
        return new AuthorizationResult(
            providerId,
            TransactionResult.CommunicationResult.SUCCESS,
            null, // providerErrorCode
            null, // errorCode
            null, // providerErrorMessage
            paymentIntent.getId(),
            customerId == null ? null : new TokenizedCreditCard(
                customerId,
                providerReplacementMaskedCardNumber,
                replacementMaskedCardNumber,
                providerReplacementExpiration,
                replacementExpirationMonth,
                replacementExpirationYear
            ),
            status, // providerApprovalResult
            AuthorizationResult.ApprovalResult.APPROVED,
            null, // providerDeclineReason
            null, // declineReason
            null, // providerReviewReason
            null, // reviewReason
            providerCvvResult,
            cvvResult,
            providerAvsResult,
            avsResult,
            approvalCode
        );
      } else {
        // All other statuses as "Hold"
        // requires_payment_method: Should not happen since we provided a payment_method
        // requires_confirmation: Should not happen since we confirm=true
        // requires_action
        // processing
        // requires_capture: Should not happen since we set capture_method=automatic
        // canceled: Should not ever be canceled

        // TODO: Need a way to pass url or map back for action, this will require API changes
        PaymentIntent.NextAction nextAction = paymentIntent.getNextAction();
        return new AuthorizationResult(
            providerId,
            TransactionResult.CommunicationResult.SUCCESS,
            null, // providerErrorCode
            null, // errorCode
            null, // providerErrorMessage
            paymentIntent.getId(),
            customerId == null ? null : new TokenizedCreditCard(
                customerId,
                providerReplacementMaskedCardNumber,
                replacementMaskedCardNumber,
                providerReplacementExpiration,
                replacementExpirationMonth,
                replacementExpirationYear
            ),
            nextAction == null ? status : nextAction.getType(), // providerApprovalResult
            AuthorizationResult.ApprovalResult.HOLD,
            null, // providerDeclineReason
            null, // declineReason
            null, // TODO: providerReviewReason
            null, // TODO: reviewReason
            providerCvvResult,
            cvvResult,
            providerAvsResult,
            avsResult,
            null // approvalCode
        );
      }
    } catch (StripeException e) {
      ConvertedError converted = convertError(creditCard.getMaskedCardNumber(), expirationMonth, expirationYear, e, null);
      if (converted.declineReason == null) {
        return new AuthorizationResult(
            providerId,
            converted.communicationResult,
            converted.providerErrorCode,
            converted.errorCode,
            converted.providerErrorMessage,
            null, // providerUniqueId
            customerId == null ? null : new TokenizedCreditCard(
                customerId,
                converted.providerReplacementMaskedCardNumber,
                converted.replacementMaskedCardNumber,
                converted.providerReplacementExpiration,
                converted.replacementExpirationMonth,
                converted.replacementExpirationYear
            ),
            null, // providerApprovalResult
            null, // approvalResult
            null, // providerDeclineReason
            null, // declineReason
            null, // providerReviewReason
            null, // reviewReason
            null, // providerCvvResult
            null, // cvvResult
            null, // providerAvsResult
            null, // avsResult
            null  // approvalCode
        );
      } else {
        // Declined
        return new AuthorizationResult(
            providerId,
            converted.communicationResult,
            null, // providerErrorCode
            null, // errorCode
            converted.providerErrorMessage,
            null, // providerUniqueId
            customerId == null ? null : new TokenizedCreditCard(
                customerId,
                converted.providerReplacementMaskedCardNumber,
                converted.replacementMaskedCardNumber,
                converted.providerReplacementExpiration,
                converted.replacementExpirationMonth,
                converted.replacementExpirationYear
            ),
            null, // providerApprovalResult
            AuthorizationResult.ApprovalResult.DECLINED, // approvalResult
            converted.providerErrorCode, // providerDeclineReason
            converted.declineReason,
            null, // providerReviewReason
            null, // reviewReason
            null, // providerCvvResult
            null, // cvvResult
            null, // providerAvsResult
            null, // avsResult
            null  // approvalCode
        );
      }
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>See <a href="https://stripe.com/docs/api/payment_intents/capture?lang=java">Capture a PaymentIntent</a>.</p>
   */
  @Override
  public CaptureResult capture(AuthorizationResult authorizationResult) {
    String id = authorizationResult.getProviderUniqueId();
    try {
      PaymentIntent intent = PaymentIntent.retrieve(id, options);
      PaymentIntentCaptureParams params;
      {
        PaymentIntentCaptureParams.Builder builder = PaymentIntentCaptureParams.builder();
        // Unused: amount_to_capture
        // Unused: application_fee_amount
        params = builder.build();
      }
      PaymentIntent captured = intent.capture(params, options);
      String status = captured.getStatus();
      if ("succeeded".equals(status)) {
        return new CaptureResult(
            providerId,
            TransactionResult.CommunicationResult.SUCCESS,
            null,
            null,
            null,
            id
        );
      } else {
        // We expect an exception, but will handle unexpected status as a failure
        return new CaptureResult(
            providerId,
            TransactionResult.CommunicationResult.GATEWAY_ERROR,
            status,
            TransactionResult.ErrorCode.APPROVED_BUT_SETTLEMENT_FAILED,
            null,
            id
        );
      }
    } catch (StripeException e) {
      ConvertedError converted = convertError(null, null, null, e, null);
      if (converted.declineReason == null) {
        return new CaptureResult(
            providerId,
            converted.communicationResult,
            converted.providerErrorCode,
            converted.errorCode,
            converted.providerErrorMessage,
            id
        );
      } else {
        // Declined should not happen here, since any decline is expected to happen on authorize
        return new CaptureResult(
            providerId,
            TransactionResult.CommunicationResult.GATEWAY_ERROR, // Decline are SUCCESS, need to convert to GATEWAY_ERROR
            converted.providerErrorCode,
            TransactionResult.ErrorCode.APPROVED_BUT_SETTLEMENT_FAILED,
            converted.providerErrorMessage,
            id
        );
      }
    }
  }

  @Override
  public VoidResult voidTransaction(Transaction transaction) {
    throw new NotImplementedException("TODO");
  }

  @Override
  public CreditResult credit(TransactionRequest transactionRequest, CreditCard creditCard) {
    throw new NotImplementedException("TODO");
  }

  @Override
  public boolean canStoreCreditCards() {
    return true;
  }

  /**
   * {@inheritDoc}
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/customers/create?lang=java">Create a customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/create?lang=java">Create a PaymentMethod</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/attach?lang=java">Attach a PaymentMethod to a Customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.</li>
   * </ol>
   */
  @Override
  public String storeCreditCard(CreditCard creditCard) throws IOException {
    try {
      // Create the Customer
      Customer customer;
      {
        CustomerCreateParams customerParams;
        {
          CustomerCreateParams.Builder builder = CustomerCreateParams.builder();
          addCustomerParams(creditCard, builder);
          customerParams = builder.build();
        }
        customer = Customer.create(customerParams, options);
      }
      // Create the payment method
      PaymentMethod paymentMethod = PaymentMethod.create(makePaymentMethodParams(creditCard), options);
      // Attach the payment method to the customer
      // TODO: During attach, AVS and CVC checks are performed.  What to do here?  Error, return, log and fail on payment? Probably API 2.0 allow CVV and AVS at this point, too
      paymentMethod.attach(
          PaymentMethodAttachParams.builder()
              .setCustomer(customer.getId())
              .build(),
          options
      );
      // Set as default payment method
      customer = customer.update(
          CustomerUpdateParams.builder()
              .setInvoiceSettings(
                  CustomerUpdateParams.InvoiceSettings.builder()
                      .setDefaultPaymentMethod(paymentMethod.getId())
                      .build()
              )
              .build(),
          options
      );
      // Return the Id of the new customer
      return customer.getId();
    } catch (StripeException e) {
      Byte expirationMonth = creditCard.getExpirationMonth(); // TODO: 3.0: Nullable Byte
      if (expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH) {
        expirationMonth = null;
      }
      Short expirationYear = creditCard.getExpirationYear(); // TODO: 3.0: Nullable Short
      if (expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR) {
        expirationYear = null;
      }
      ConvertedError converted = convertError(creditCard.getMaskedCardNumber(), expirationMonth, expirationYear, e, null);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.storeCreditCard.notSuccessful");
    }
  }

  /**
   * {@inheritDoc}
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/update?lang=java">Update a PaymentMethod</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/delete?lang=java">Delete a card</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/update?lang=java">Update a card</a>.</li>
   * </ol>
   */
  @Override
  public void updateCreditCard(CreditCard creditCard) throws IOException {
    try {
      // Find the customer
      Customer customer = Customer.retrieve(
          creditCard.getProviderUniqueId(),
          // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
          CustomerRetrieveParams.builder().addExpand("sources").build(),
          options
      );
      // Update the Customer
      if (UPDATE_WITH_MAP_API) {
        Map<String, Object> customerParams = new HashMap<>();
        addCustomerParams(creditCard, true, customerParams);
        // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
        customerParams.put("expand", Collections.singletonList("sources"));
        customer = customer.update(customerParams, options);
      } else {
        CustomerUpdateParams.Builder builder = CustomerUpdateParams.builder();
        addCustomerParams(creditCard, builder);
        // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
        builder.addExpand("sources");
        customer = customer.update(builder.build(), options);
      }

      String paymentMethodId;
      {
        Pair<Customer, String> combined = getDefaultPaymentMethodId(customer);
        customer = combined.getKey();
        paymentMethodId = combined.getValue();
      }
      String defaultSource = customer.getDefaultSource();
      if (paymentMethodId != null) {
        // Find the PaymentMethod
        PaymentMethod defaultPaymentMethod = PaymentMethod.retrieve(paymentMethodId, options);
        // Update PaymentMethod
        PaymentMethodUpdateParams paymentMethodParams;
        {
          PaymentMethodUpdateParams.Builder builder = PaymentMethodUpdateParams.builder();
          addPaymentMethodParams(creditCard, builder);
          paymentMethodParams = builder.build();
        }
        defaultPaymentMethod.update(paymentMethodParams, options);
        // Check for incomplete conversion to PaymentMethod
        if (defaultSource != null) {
          // Incomplete conversion to PaymentMethod, remove old default source
          Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
          defaultCard.delete(options);
        }
      } else {
        // Find the default Card
        Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
        // Update the default Card
        if (UPDATE_WITH_MAP_API) {
          Map<String, Object> cardParams = new HashMap<>();
          addCardParams(creditCard, true, cardParams);
          defaultCard.update(cardParams, options);
        } else {
          CardUpdateOnCustomerParams.Builder builder = CardUpdateOnCustomerParams.builder();
          addCardParams(creditCard, builder);
          defaultCard.update(builder.build(), options);
        }
      }
    } catch (StripeException e) {
      Byte expirationMonth = creditCard.getExpirationMonth(); // TODO: 3.0: Nullable Byte
      if (expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH) {
        expirationMonth = null;
      }
      Short expirationYear = creditCard.getExpirationYear(); // TODO: 3.0: Nullable Short
      if (expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR) {
        expirationYear = null;
      }
      ConvertedError converted = convertError(creditCard.getMaskedCardNumber(), expirationMonth, expirationYear, e, null);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.updateCreditCardNumberAndExpiration.notSuccessful");
    }
  }

  /**
   * {@inheritDoc}
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/create?lang=java">Create a PaymentMethod</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/attach?lang=java">Attach a PaymentMethod to a Customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/customers/update?lang=java">Update a customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/detach?lang=java">Detach a PaymentMethod from a Customer</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/delete?lang=java">Delete a card</a>.</li>
   * </ol>
   */
  @Override
  public void updateCreditCardNumberAndExpiration(
      CreditCard creditCard,
      String cardNumber,
      byte expirationMonth,
      short expirationYear,
      String cardCode
  ) throws IOException {
    try {
      // Find the customer
      Customer customer = Customer.retrieve(
          creditCard.getProviderUniqueId(),
          // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
          CustomerRetrieveParams.builder().addExpand("sources").build(),
          options
      );

      final String paymentMethodId;
      {
        Pair<Customer, String> combined = getDefaultPaymentMethodId(customer);
        customer = combined.getKey();
        paymentMethodId = combined.getValue();
      }
      final String defaultSource = customer.getDefaultSource();

      // Create the payment method
      final PaymentMethod paymentMethod = PaymentMethod.create(
          makePaymentMethodParams(
              creditCard,
              cardNumber,
              expirationMonth,
              expirationYear,
              cardCode != null ? CreditCard.numbersOnly(cardCode) : creditCard.getCardCode()
          ),
          options
      );
      // Attach the payment method to the customer
      // TODO: During attach, AVS and CVC checks are performed.  What to do here?  Error, return, log and fail on payment? Probably API 2.0 allow CVV and AVS at this point, too
      paymentMethod.attach(
          PaymentMethodAttachParams.builder()
              .setCustomer(customer.getId())
              .build(),
          options
      );
      // Set as default payment method
      customer = customer.update(
          CustomerUpdateParams.builder()
              .setInvoiceSettings(
                  CustomerUpdateParams.InvoiceSettings.builder()
                      .setDefaultPaymentMethod(paymentMethod.getId())
                      .build()
              )
              // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
              .addExpand("sources")
              .build(),
          options
      );

      if (paymentMethodId != null) {
        // Find old PaymentMethod
        PaymentMethod oldPaymentMethod = PaymentMethod.retrieve(paymentMethodId, options);
        // Detach old PaymentMethod
        oldPaymentMethod.detach(options);
      }

      if (defaultSource != null) {
        // Conversion to PaymentMethod, remove old default source
        Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
        defaultCard.delete(options);
      }
    } catch (StripeException e) {
      ConvertedError converted = convertError(CreditCard.maskCreditCardNumber(cardNumber), expirationMonth, expirationYear, e, null);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.updateCreditCardNumberAndExpiration.notSuccessful");
    }
  }

  private static String zeroPad(byte month) {
    if (month < 10) {
      return "0" + month;
    }
    return Byte.toString(month);
  }

  /**
   * {@inheritDoc}
   * <ol>
   * <li>See <a href="https://stripe.com/docs/api/payment_methods/update?lang=java">Update a PaymentMethod</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/delete?lang=java">Delete a card</a>.</li>
   * <li>See <a href="https://stripe.com/docs/api/cards/update?lang=java">Update a card</a>.</li>
   * </ol>
   */
  @Override
  public void updateCreditCardExpiration(
      CreditCard creditCard,
      byte expirationMonth,
      short expirationYear
  ) throws IOException {
    try {
      // Find the customer
      Customer customer = Customer.retrieve(
          creditCard.getProviderUniqueId(),
          // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
          CustomerRetrieveParams.builder().addExpand("sources").build(),
          options
      );

      String paymentMethodId;
      {
        Pair<Customer, String> combined = getDefaultPaymentMethodId(customer);
        customer = combined.getKey();
        paymentMethodId = combined.getValue();
      }
      String defaultSource = customer.getDefaultSource();

      if (paymentMethodId != null) {
        // Find the PaymentMethod
        PaymentMethod defaultPaymentMethod = PaymentMethod.retrieve(paymentMethodId, options);
        // Update PaymentMethod
        defaultPaymentMethod.update(
            PaymentMethodUpdateParams.builder()
                .setCard(
                    PaymentMethodUpdateParams.Card.builder()
                        .setExpMonth((long) expirationMonth)
                        .setExpYear((long) expirationYear)
                        .build()
                )
                .build(),
            options
        );
        // Check for incomplete conversion to PaymentMethod
        if (defaultSource != null) {
          // Incomplete conversion to PaymentMethod, remove old default source
          Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
          defaultCard.delete(options);
        }
      } else {
        // Find the default Card
        Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
        // Update the default Card
        defaultCard.update(
            CardUpdateOnCustomerParams.builder()
                .setExpMonth(expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH ? null : zeroPad(expirationMonth))
                .setExpYear(expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR ? null : Short.toString(expirationYear))
                .build(),
            options
        );
      }
    } catch (StripeException e) {
      ConvertedError converted = convertError(creditCard.getMaskedCardNumber(), expirationMonth, expirationYear, e, null);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.updateCreditCardExpiration.notSuccessful");
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>See <a href="https://stripe.com/docs/api/customers/delete?lang=java">Delete a customer</a>.</p>
   */
  @Override
  public void deleteCreditCard(CreditCard creditCard) throws IOException {
    try {
      Customer customer = Customer.retrieve(creditCard.getProviderUniqueId(), options);
      if (customer.getDeleted() == null || !customer.getDeleted()) {
        customer.delete(options);
      }
    } catch (StripeException e) {
      Byte expirationMonth = creditCard.getExpirationMonth(); // TODO: 3.0: Nullable Byte
      if (expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH) {
        expirationMonth = null;
      }
      Short expirationYear = creditCard.getExpirationYear(); // TODO: 3.0: Nullable Short
      if (expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR) {
        expirationYear = null;
      }
      ConvertedError converted = convertError(creditCard.getMaskedCardNumber(), expirationMonth, expirationYear, e, null);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.deleteCreditCard.notSuccessful");
    }
  }

  @Override
  public boolean canGetTokenizedCreditCards() {
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * <p>See <a href="https://stripe.com/docs/api/customers/list?lang=java">List all customers</a>.</p>
   */
  @Override
  @SuppressWarnings("AssignmentToForLoopParameter")
  public Map<String, TokenizedCreditCard> getTokenizedCreditCards(Map<String, CreditCard> persistedCards, PrintWriter verboseOut, PrintWriter infoOut, PrintWriter warningOut) throws IOException {
    try {
      Map<String, TokenizedCreditCard> map = AoCollections.newLinkedHashMap(persistedCards.size());
      String startingAfter = null;
      List<Customer> customers;
      while (
          !(customers = Customer.list(
              CustomerListParams.builder()
                  .setLimit(100L)
                  .setStartingAfter(startingAfter)
                  // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
                  .addExpand("data.sources")
                  .build(),
              options
          ).getData()).isEmpty()
      ) {
        if (verboseOut != null) {
          verboseOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getTokenizedCreditCards: customers.size() = " + customers.size());
        }
        for (Customer customer : customers) {
          String customerId = customer.getId();
          startingAfter = customerId;

          // Find the default payment method card settings
          String brand;
          String last4;
          Byte expMonth;
          Short expYear;
          {
            String paymentMethodId;
            {
              Pair<Customer, String> combined = getDefaultPaymentMethodId(
                  Customer.retrieve(
                      customerId,
                      // "sources" no longer included by default: https://stripe.com/docs/upgrades#2020-08-27
                      CustomerRetrieveParams.builder().addExpand("sources").build(),
                      options
                  )
              );
              customer = combined.getKey();
              paymentMethodId = combined.getValue();
            }
            if (paymentMethodId != null) {
              PaymentMethod defaultPaymentMethod = PaymentMethod.retrieve(paymentMethodId, options);
              PaymentMethod.Card defaultCard = defaultPaymentMethod.getCard();
              brand = defaultCard.getBrand();
              last4 = defaultCard.getLast4();
              expMonth = safeCastMonth(defaultCard.getExpMonth());
              expYear = safeCastYear(defaultCard.getExpYear());
            } else {
              // Look for a default source for backward compatibility
              String defaultSource = customer.getDefaultSource();
              if (defaultSource != null) {
                Card defaultCard = (Card) customer.getSources().retrieve(defaultSource, options);
                brand = defaultCard.getBrand();
                last4 = defaultCard.getLast4();
                expMonth = safeCastMonth(defaultCard.getExpMonth());
                expYear = safeCastYear(defaultCard.getExpYear());
              } else {
                if (warningOut != null) {
                  warningOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getTokenizedCreditCards: Customer does not have any default source: " + customerId);
                } else if (logger.isLoggable(Level.WARNING)) {
                  logger.log(Level.WARNING, "Customer does not have any default source: " + customerId);
                }
                brand = null;
                last4 = null;
                expMonth = null;
                expYear = null;
              }
            }
          }
          // Find the persisted card
          CreditCard persistedCard = persistedCards.get(customerId);
          // Detect any updated expiration date
          Byte replacementExpirationMonth;
          Short replacementExpirationYear;
          {
            // Find the current expiration, if known
            Byte expirationMonth;
            Short expirationYear;
            if (persistedCard != null) {
              expirationMonth = persistedCard.getExpirationMonth(); // TODO: 3.0: Make nullable Byte
              if (expirationMonth == CreditCard.UNKNOWN_EXPIRATION_MONTH) {
                expirationMonth = null;
              }
              expirationYear = persistedCard.getExpirationYear(); // TODO: 3.0: Make nullable Short
              if (expirationYear == CreditCard.UNKNOWN_EXPIRATION_YEAR) {
                expirationYear = null;
              }
            } else {
              expirationMonth = null;
              expirationYear = null;
            }
            if (
                expirationMonth == null || !expirationMonth.equals(expMonth)
                    || expirationYear == null || !expirationYear.equals(expYear)
            ) {
              // Changed
              replacementExpirationMonth = expMonth;
              replacementExpirationYear = expYear;
            } else {
              // Not changed
              replacementExpirationMonth = null;
              replacementExpirationYear = null;
            }
          }

          TokenizedCreditCard card = new TokenizedCreditCard(
              customerId,
              getProviderReplacementCombined(brand, last4),
              getReplacementMaskedCardNumber(persistedCard == null ? null : persistedCard.getMaskedCardNumber(), brand, last4, warningOut),
              getProviderReplacementCombined(expMonth, expYear),
              replacementExpirationMonth,
              replacementExpirationYear
          );
          if (verboseOut != null) {
            verboseOut.println(Stripe.class.getSimpleName() + "(" + providerId + ").getTokenizedCreditCards: providerUniqueId: " + card.getProviderUniqueId() + " ↵");
            verboseOut.println("    providerReplacementMaskedCardNumber: " + card.getProviderReplacementMaskedCardNumber());
            verboseOut.println("    replacementMaskedCardNumber........: " + card.getReplacementMaskedCardNumber());
            verboseOut.println("    providerReplacementExpiration......: " + card.getProviderReplacementExpiration());
            verboseOut.println("    replacementExpiration..............: " + card.getReplacementExpirationMonth() + CreditCard.EXPIRATION_DISPLAY_SEPARATOR + card.getReplacementExpirationYear());
          }
          if (map.put(customerId, card) != null) {
            throw new IOException("Duplicate customerId: " + customerId);
          }
        }
      }
      return Collections.unmodifiableMap(map);
    } catch (StripeException e) {
      ConvertedError converted = convertError(null, null, null, e, warningOut);
      // TODO: Throw ErrorCodeException to provide more details
      throw new LocalizedIOException(e, PACKAGE_RESOURCES, "MerchantServicesProvider.getTokenizedCreditCards.notSuccessful");
    }
  }
}
