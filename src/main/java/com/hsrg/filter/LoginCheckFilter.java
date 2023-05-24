package com.hsrg.filter;

import com.hsrg.utils.JwtUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class LoginCheckFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain filterChain) {
        ServerHttpRequest req=  exchange.getRequest();
        ServerHttpResponse resp = exchange.getResponse();

        //1.获取url
        String url = req.getURI().getPath();
        log.info("请求的url:{}",url);

        //2.判断url是否是login或register
        if(req.getMethod().toString().equals("POST")){
            if(url.equals("/auth/login")){
                log.info("登录操作直接放行");
                return filterChain.filter(exchange);
            }
            else if(url.equals("/auth/adminLogin")){
                log.info("管理员登录操作直接放行");
                return filterChain.filter(exchange);
            }
            else if(url.equals("/auth/register")){
                log.info("注册操作直接放行");
                return filterChain.filter(exchange);
            }
        }

        //3.获取请求头令牌(token)
        String jwt = req.getHeaders().getFirst("Authorization");

        //4.判断令牌是否存在，不存在返回错误结果，未登录
        if(!StringUtils.hasLength(jwt)){
            log.info("请求头token为空，返回未登录信息");
            resp.setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
//       5.解析令牌，如果失败，返回错误结果
        try {
            JwtUtils.parseJWT(jwt);
        } catch (Exception e) {//解析失败
            e.printStackTrace();
            log.info("解析令牌失败，返回未登录错误信息");
            resp.setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
//        6.放行
        log.info("持有合法令牌，放行");
        return filterChain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
