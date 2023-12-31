package pro.gravit.simplecabinet.web.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pro.gravit.simplecabinet.web.model.ExchangeRate;

import java.util.List;
import java.util.Optional;

public interface ExchangeRateRepository extends JpaRepository<ExchangeRate, Long> {
    Optional<ExchangeRate> findExchangeRateByFromCurrencyAndToCurrency(String fromCurrency, String toCurrency);

    List<ExchangeRate> findExchangeRateByFromCurrency(String fromCurrency);
}
