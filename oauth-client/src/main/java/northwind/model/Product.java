package northwind.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Java record representing a Product from the Northwind database
 * This record maps to the product.json file structure
 */
//ignore unknown properties
@JsonIgnoreProperties(ignoreUnknown = true)
public record Product(
    @JsonProperty("ProductID")
    Integer productId,
    
    @JsonProperty("ProductName")
    String productName,
    
    @JsonProperty("SupplierID")
    Integer supplierId,
    
    @JsonProperty("CategoryID")
    Integer categoryId,
    
    @JsonProperty("QuantityPerUnit")
    String quantityPerUnit,
    
    @JsonProperty("UnitPrice")
    Double unitPrice,
    
    @JsonProperty("UnitsInStock")
    Integer unitsInStock,
    
    @JsonProperty("UnitsOnOrder")
    Integer unitsOnOrder,
    
    @JsonProperty("ReorderLevel")
    Integer reorderLevel,
    
    @JsonProperty("Discontinued")
    Boolean discontinued
) {
    
    /**
     * Validation constructor
     */
    public Product {
        if (productName == null || productName.trim().isEmpty()) {
            throw new IllegalArgumentException("Product name cannot be null or empty");
        }
        if (unitPrice != null && unitPrice < 0) {
            throw new IllegalArgumentException("Unit price cannot be negative");
        }
    }
    
    /**
     * Convenience constructor for creating a Product with minimal required fields
     */
    public Product(String productName, Double unitPrice) {
        this(null, productName, null, null, null, unitPrice, null, null, null, false);
    }
    
    /**
     * Check if the product is available in stock
     */
    public boolean isInStock() {
        return unitsInStock != null && unitsInStock > 0;
    }
    
    /**
     * Check if the product needs to be reordered
     */
    public boolean needsReorder() {
        return reorderLevel != null && unitsInStock != null && unitsInStock <= reorderLevel;
    }
    
    /**
     * Get the total value of units in stock
     */
    public Double getStockValue() {
        if (unitPrice == null || unitsInStock == null) {
            return null;
        }
        return unitPrice * unitsInStock;
    }
    
    /**
     * Check if product is active (not discontinued)
     */
    public boolean isActive() {
        return discontinued == null || !discontinued;
    }
}