package com.example.springboot3oauth2authorizationserver.security;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * Jackson 라이브러리를 사용하여 JSON 직렬화 및 역직렬화 커스터마이징
 * CustomUserPrincipal 클래스에는 적용할 수 없는 Jackson 어노테이션을 추가하고자 할 때 사용
 * */

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, // 모든 필드에 시리얼라이즈를 허용
        getterVisibility = JsonAutoDetect.Visibility.NONE, // 게터 메서드에 대한 시리얼라이즈를 금지
        isGetterVisibility = JsonAutoDetect.Visibility.NONE) // is-형식의 불리언 게터 메서드에 대한 시리얼라이즈를 금지
@JsonIgnoreProperties(ignoreUnknown = true) // JSON에는 존재하지만 클래스에는 매핑되지 않은 속성들을 무시
@JsonDeserialize(using = CustomUserPrincipalDeserializer.class) // 역직렬화할 때 특정한 커스텀 역직렬화 클래스(CustomUserPrincipalDeserializer)를 사용하도록 지정
public class CustomUserPrincipalMixin {

}
